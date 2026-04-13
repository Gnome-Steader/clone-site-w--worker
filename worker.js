const upstream = 'www.gimkit.com';
const upstream_mobile = null;
const upstream_path = '/';
const upstream_allow_override = false;
const upstream_get_parameter = 'CORSflare_upstream';
const blocked_regions = ['CN', 'KP', 'SY', 'PK', 'CU'];
const blocked_ip_addresses = ['0.0.0.0', '127.0.0.1'];
const https = true;
const set_cookie_samesite_none = false;
const http_response_headers_set = {
    'X-Frame-Options': 'ALLOW FROM https://www.example.com', 
    'Content-Security-Policy': "frame-ancestors 'self' https://www.example.com;", 
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': true,
};
const http_response_headers_delete = [
    'Content-Security-Policy-Report-Only',
    'Clear-Site-Data'
];
const replacement_rules = {
    'http://{upstream_hostname}/': 'https://{proxy_hostname}/',
    '{upstream_hostname}': '{proxy_hostname}',
}
const replacement_content_types = ['text/html'];
const replacement_use_regex = true;
var regexp_upstreamHostname = (replacement_use_regex)
    ? new RegExp('{upstream_hostname}', 'g')
    : null;
var regexp_proxyHostname = (replacement_use_regex)
    ? new RegExp('{proxy_hostname}', 'g')
    : null;
addEventListener('fetch', event => {
    event.respondWith(fetchAndApply(event.request));
})
async function fetchAndApply(request) {
    var r = request.headers.get('cf-ipcountry');
    const region = (r) ? r.toUpperCase() : null;
    const ip_address = request.headers.get('cf-connecting-ip');
    const user_agent = request.headers.get('user-agent');
    let response = null;
    let url = new URL(request.url);
    let url_hostname = url.hostname;
    let upstream_GET = (upstream_allow_override) ? url.searchParams.get(upstream_get_parameter) : null;
    if (https == true) {
        url.protocol = 'https:';
    } else {
        url.protocol = 'http:';
    }
    var upstream_domain = null;
    if (upstream_GET) {
        upstream_domain = upstream_GET;
    }
    else if (upstream_mobile && await is_mobile_user_agent(user_agent)) {
        upstream_domain = upstream_mobile;
    }
    else {
        upstream_domain = upstream;
    }
    url.host = upstream_domain;
    if (url.pathname == '/') {
        url.pathname = upstream_path;
    } else {
        url.pathname = upstream_path + url.pathname;
    }
    if (blocked_regions.includes(region) || blocked_ip_addresses.includes(ip_address)) {
        response = new Response('Access denied', {
            status: 403
        });
    } else {
        let method = request.method;
        let request_headers = request.headers;
        let new_request_headers = new Headers(request_headers);
        let request_content_type = new_request_headers.get('content-type');
        new_request_headers.set('Host', upstream_domain);
        new_request_headers.set('Origin', upstream_domain);
        new_request_headers.set('Referer', url.protocol + '
        var params = {
            method: method,
            headers: new_request_headers,
            redirect: 'manual'
        }
        if (method.toUpperCase() === "POST" && request_content_type) {
            let request_content_type_toLower = request_content_type.toLowerCase();
            if (request_content_type_toLower.includes("application/x-www-form-urlencoded")
                || request_content_type_toLower.includes("multipart/form-data")
                || request_content_type_toLower.includes("application/json")
            ) {
                let reqText = await request.text(); 
                if (reqText) {
                    params.body = reqText;
                }
            }
        }
        let original_response = await fetch(url.href, params);
        connection_upgrade = new_request_headers.get("Upgrade");
        if (connection_upgrade && connection_upgrade.toLowerCase() == "websocket") {
            return original_response;
        }
        let original_response_clone = original_response.clone();
        let response_headers = original_response_clone.headers;
        let response_status = original_response_clone.status;
        let original_text = null;
        let new_response_headers = new Headers(response_headers);
        let new_response_status = response_status;
        if (http_response_headers_set) {
            for (let k in http_response_headers_set) {
                var v = http_response_headers_set[k];
                new_response_headers.set(k, v);
            }
        }
        if (http_response_headers_delete) {
            for (let k of http_response_headers_delete) {
                new_response_headers.delete(k);
            }
        }
        if (new_response_headers.get("x-pjax-url")) {
            new_response_headers.set("x-pjax-url", new_response_headers.get("x-pjax-url")
                .replace(url.protocol + "
                .replace(upstream_domain, url_hostname));
        }
        if (new_response_headers.get("location")) {
            var location = new_response_headers.get("location");
            if (upstream_allow_override && location.includes("googleusercontent.com")) {
                var new_upstream = location.substring(8, location.indexOf("/", 8));
                location = location + "&" + upstream_get_parameter + "=" + new_upstream;
                new_response_headers.set("location", location
                    .replace(url.protocol + "
                    .replace(new_upstream, url_hostname));
            }
            else {
                new_response_headers.set("location", location
                    .replace(url.protocol + "
                    .replace(upstream_domain, url_hostname));
            }
        }
        if (set_cookie_samesite_none && new_response_headers.has("set-cookie")) {
            var firstCookie = new_response_headers.get("set-cookie").split(',').shift();
            new_response_headers.set("set-cookie", firstCookie
                .split("SameSite=Lax; Secure").join("")
                .split("SameSite=Lax").join("")
                .split("SameSite=Strict; Secure").join("")
                .split("SameSite=Strict").join("")
                .split("SameSite=None; Secure").join("")
                .split("SameSite=None").join("")
                .replace(/^;+$/g, '')
                + "; SameSite=None; Secure");
        }
        let response_content_type = new_response_headers.get('content-type');
        if (response_content_type
            && replacement_content_types.some(v => response_content_type.toLowerCase().includes(v))) {
            original_text = await replace_response_text(original_response_clone, upstream_domain, url_hostname);
        } else {
            original_text = original_response_clone.body;
        }
        response = new Response(original_text, {
            status: new_response_status,
            headers: new_response_headers
        })
    }
    return response;
}
async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text()
    if (replacement_rules) {
        for (let k in replacement_rules) {
            var v = replacement_rules[k];
            if (replacement_use_regex) {
                k = k.replace(regexp_upstreamHostname, upstream_domain);
                k = k.replace(regexp_proxyHostname, host_name);
                v = v.replace(regexp_upstreamHostname, upstream_domain);
                v = v.replace(regexp_proxyHostname, host_name);
                text = text.replace(new RegExp(k, 'g'), v);
            }
            else {
                k = k.split('{upstream_hostname}').join(upstream_domain);
                k = k.split('{proxy_hostname}').join(host_name);
                v = v.split('{upstream_hostname}').join(upstream_domain);
                v = v.split('{proxy_hostname}').join(host_name);
                text = text.split(k).join(v);
            }
        }
    }
    return text;
}
async function is_mobile_user_agent(user_agent_info) {
    var agents = ["Android", "iPhone", "SymbianOS", "Windows Phone", "iPad", "iPod"];
    for (var v = 0; v < agents.length; v++) {
        if (user_agent_info.indexOf(agents[v]) > 0) {
            return true;
        }
    }
    return false;
}
