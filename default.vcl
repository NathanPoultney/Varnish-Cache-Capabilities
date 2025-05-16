vcl 4.1;

import std;
import directors;

# Custom C module for advanced header manipulation
import headerplus;

# Backend definitions
backend default {
    .host = "192.168.1.10";
    .port = "8080";
    .max_connections = 300;
    .first_byte_timeout = 15s;
    .between_bytes_timeout = 5s;
    .connect_timeout = 3s;
    
    # Health check
    .probe = {
        .url = "/health";
        .timeout = 1s;
        .interval = 5s;
        .window = 5;
        .threshold = 3;
    }
}

backend api_server {
    .host = "192.168.1.20";
    .port = "8081";
    .max_connections = 200;
}

backend admin_panel {
    .host = "192.168.1.30";
    .port = "8082";
}

# ACL for trusted IPs
acl trusted {
    "localhost";
    "192.168.0.0"/24;
    "10.0.0.0"/8;
}

# Secret key for JWT validation
sub vcl_init {
    # Initialise the load balancing director
    new api_cluster = directors.round_robin();
    api_cluster.add_backend(api_server);
    api_cluster.add_backend(default);
    
    # Set up a counter for rate limiting
    new rate_limiter = std.counter();
    
    # Initialise shared memory segments for distributed rate limiting
    new rate_limit_data = std.shmlog("rate_limits", 64M);
}

# Custom function for base64 auth validation
sub authenticate_user {
    # Basic auth credentials
    if (!req.http.Authorisation ~ "^Basic ") {
        return false;
    }
    
    # Extract and decode the credentials
    set req.http.Auth = regsub(req.http.Authorisation, "^Basic ", "");
    set req.http.Auth = std.base64decode(req.http.Auth);
    
    # Check against our credential store (simplified example)
    if (req.http.Auth == "admin:secret_password" || 
        req.http.Auth == "api_user:api_password") {
        return true;
    }
    
    return false;
}

# CORS handling
sub handle_cors {
    if (req.method == "OPTIONS") {
        # Handle preflight requests
        return(synth(200, "OK"));
    }
    
    # Set CORS headers for actual requests
    set resp.http.Access-Control-Allow-Origin = "*";
    set resp.http.Access-Control-Allow-Methods = "GET, POST, PUT, DELETE, OPTIONS";
    set resp.http.Access-Control-Allow-Headers = "Content-Type, Authorisation, X-Requested-With";
    set resp.http.Access-Control-Max-Age = "86400";
}

# Function to set appropriate Vary headers
sub set_vary_headers {
    # Ensure proper cache variations
    if (req.http.Accept-Encoding) {
        if (resp.http.Vary) {
            set resp.http.Vary = resp.http.Vary + ", Accept-Encoding";
        } else {
            set resp.http.Vary = "Accept-Encoding";
        }
    }
    
    # Also vary on User-Agent for mobile-specific content
    if (req.http.User-Agent ~ "Mobile|Android|iPhone|iPad") {
        if (resp.http.Vary) {
            set resp.http.Vary = resp.http.Vary + ", User-Agent";
        } else {
            set resp.http.Vary = "User-Agent";
        }
    }
}

# Custom request normalization
sub normalize_request {
    # Normalize query string parameters order
    if (req.url ~ "\?") {
        set req.url = std.querysort(req.url);
    }
    
    # Remove certain cookies that don't affect the response
    if (req.http.Cookie) {
        set req.http.Cookie = regsuball(req.http.Cookie, "(^|; )(analytics_token|_ga|_gid)=[^;]*", "");
        # Clean up empty or semicolon-only cookies
        if (req.http.Cookie ~ "^ *$") {
            unset req.http.Cookie;
        }
    }
}

# Detect device type
sub detect_device {
    if (req.http.User-Agent ~ "(?i)mobile|android|iphone|ipad|ipod") {
        set req.http.X-Device-Type = "mobile";
    } else {
        set req.http.X-Device-Type = "desktop";
    }
}

# Request processing
sub vcl_recv {
    # Basic routing
    if (req.url ~ "^/api/") {
        # Use the API director for load balancing
        set req.backend_hint = api_cluster.backend();
    } elsif (req.url ~ "^/admin/") {
        # Admin panel backend
        set req.backend_hint = admin_panel;
    } else {
        # Default backend
        set req.backend_hint = default;
    }
    
    # Apply rate limiting for API
    if (req.url ~ "^/api/") {
        # Get client IP (respecting X-Forwarded-For if from trusted source)
        if (req.http.X-Forwarded-For && client.ip ~ trusted) {
            set req.http.X-Client-IP = regsub(req.http.X-Forwarded-For, "[, ].*", "");
        } else {
            set req.http.X-Client-IP = client.ip;
        }
        
        # Create a rate limit key combining IP and API endpoint
        set req.http.Rate-Key = req.http.X-Client-IP + "_" + regsub(req.url, "^/api/([^/]*).*", "\1");
        
        # Check rate limit (100 requests per minute)
        if (rate_limiter.inc(req.http.Rate-Key, 60) > 100) {
            return(synth(429, "Rate limit exceeded"));
        }
    }
    
    # Handle PURGE requests (cache invalidation)
    if (req.method == "PURGE") {
        if (client.ip ~ trusted) {
            return(purge);
        } else {
            return(synth(403, "Forbidden"));
        }
    }
    
    # Authentication for admin area
    if (req.url ~ "^/admin/") {
        if (!client.ip ~ trusted && !authenticate_user()) {
            return(synth(401, "Authentication required"));
        }
    }
    
    # API authentication using JWT
    if (req.url ~ "^/api/private/") {
        # Check for JWT token
        if (!req.http.Authorisation ~ "^Bearer ") {
            return(synth(401, "JWT token required"));
        }
        
        # JWT validation would go here (simplified)
        set req.http.Auth-Token = regsub(req.http.Authorisation, "^Bearer ", "");
        if (req.http.Auth-Token != "valid_token_placeholder") {
            return(synth(403, "Invalid token"));
        }
    }
    
    # Device detection for responsive content
    call detect_device;
    
    # Request normalization
    call normalize_request;
    
    # Do not cache requests with authorisation or certain cookies
    if (req.http.Authorisation || 
        (req.http.Cookie && req.http.Cookie ~ "session|login|auth")) {
        return(pass);
    }
    
    # Cache GET and HEAD requests by default
    if (req.method != "GET" && req.method != "HEAD") {
        return(pass);
    }
    
    # Strip cookies for static assets
    if (req.url ~ "(?i)\.(png|gif|jpeg|jpg|ico|swf|css|js|html|htm|woff|woff2)(\?[a-z0-9]+)?$") {
        unset req.http.Cookie;
    }
    
    # Hash based on X-Device-Type for responsive content
    if (req.http.X-Device-Type) {
        hash_data(req.http.X-Device-Type);
    }
    
    # Default behavior: lookup cache
    return(hash);
}

# Hash customisation
sub vcl_hash {
    # Default hash data
    hash_data(req.url);
    
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }
    
    # Language-based caching
    if (req.http.Accept-Language) {
        hash_data(regsub(req.http.Accept-Language, "^([a-z]{2}).*", "\1"));
    }
    
    # Currency or country-specific content
    if (req.http.X-Country-Code) {
        hash_data(req.http.X-Country-Code);
    }
    
    return(lookup);
}

# Backend response processing
sub vcl_backend_response {
    # Set default TTL if not specified
    if (!beresp.ttl > 0s) {
        set beresp.ttl = 1h;
    }
    
    # Do not cache backend errors
    if (beresp.status >= 500) {
        set beresp.ttl = 0s;
        set beresp.uncacheable = true;
        return(deliver);
    }
    
    # Specify caching rules based on URL patterns
    if (bereq.url ~ "^/api/public/") {
        set beresp.ttl = 5m;  # Short TTL for API responses
    } elsif (bereq.url ~ "(?i)\.(jpg|jpeg|png|gif|ico|css|js)(\?[a-z0-9]+)?$") {
        set beresp.ttl = 7d;  # Cache static assets for a week
        
        # Add Grace period for static assets
        set beresp.grace = 24h;
    } elsif (bereq.url ~ "^/news/") {
        set beresp.ttl = 10m;  # News content updates frequently
    }
    
    # Set a longer grace period for all objects
    if (beresp.ttl > 0s) {
        set beresp.grace = 1h;
    }
    
    # Gzip compressible content if not already compressed
    if (beresp.http.content-type ~ "text|application/json|application/javascript") {
        if (!beresp.http.content-encoding || beresp.http.content-encoding !~ "gzip") {
            set beresp.do_gzip = true;
        }
    }
    
    # Large objects get streamed
    if (beresp.http.content-length ~ "[0-9]{8,}") {
        set beresp.do_stream = true;
    }
    
    # Don't cache objects with Set-Cookie
    if (beresp.http.Set-Cookie) {
        set beresp.uncacheable = true;
        return(deliver);
    }
    
    # Don't cache authenticated responses
    if (bereq.http.Authorisation) {
        set beresp.uncacheable = true;
        return(deliver);
    }
    
    # Set cache tags for selective purging
    if (bereq.url ~ "^/product/") {
        set beresp.http.X-Cache-Tag = "products";
    } elsif (bereq.url ~ "^/category/") {
        set beresp.http.X-Cache-Tag = "categories";
    }
    
    # Remove backend cookies for caching
    unset beresp.http.Set-Cookie;
    
    return(deliver);
}

# Response processing
sub vcl_deliver {
    # Add debug info in headers for troubleshooting
    if (req.http.X-Debug == "true" && client.ip ~ trusted) {
        set resp.http.X-Cache = req.http.X-Cache;
        set resp.http.X-Cache-Hits = obj.hits;
        set resp.http.X-Backend = req.backend_hint;
        set resp.http.X-Device-Type = req.http.X-Device-Type;
    } else {
        # Remove internal headers
        unset resp.http.X-Varnish;
        unset resp.http.Via;
        unset resp.http.X-Cache-Tag;
        unset resp.http.X-Powered-By;
    }
    
    # Add security headers
    set resp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains";
    set resp.http.X-Content-Type-Options = "nosniff";
    set resp.http.X-Frame-Options = "SAMEORIGIN";
    set resp.http.X-XSS-Protection = "1; mode=block";
    
    # Handle CORS
    call handle_cors;
    
    # Set appropriate Vary headers
    call set_vary_headers;
    
    # Content-specific headers
    if (resp.http.Content-Type ~ "application/json") {
        # Add content type enforcement for JSON
        set resp.http.X-Content-Type-Options = "nosniff";
    }
    
    return(deliver);
}

# Error handling
sub vcl_synth {
    set resp.http.Content-Type = "application/json";
    
    # Custom error responses
    if (resp.status == 401) {
        set resp.http.WWW-Authenticate = "Basic realm=Restricted";
        set resp.body = "{\"error\": \"Authentication required\", \"status\": 401}";
    } elsif (resp.status == 429) {
        set resp.body = "{\"error\": \"Rate limit exceeded\", \"status\": 429}";
    } elsif (resp.status == 403) {
        set resp.body = "{\"error\": \"Access forbidden\", \"status\": 403}";
    } else {
        set resp.body = "{\"error\": \"" + resp.reason + "\", \"status\": " + resp.status + "}";
    }
    
    # Add security headers to synthetic responses too
    set resp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains";
    set resp.http.X-Content-Type-Options = "nosniff";
    
    return(deliver);
}

# Handle ESI (Edge Side Includes)
sub vcl_backend_fetch {
    if (bereq.url ~ "\.esi$") {
        set bereq.http.X-ESI-Request = "true";
    }
    
    return(fetch);
}