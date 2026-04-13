const upstream = 'www.gimkit.com';
const upstream_mobile = null;
const upstream_path = '/';
const upstream_allow_override = false;
const upstream_get_parameter = 'gimods_injector_upstream';
const blocked_regions = ['CN', 'KP', 'SY', 'PK', 'CU'];
const blocked_ip_addresses = ['0.0.0.0', '127.0.0.1'];
const https = true;
const set_cookie_samesite_none = false;

const http_response_headers_set = {
  'X-Frame-Options': 'ALLOW FROM https://www.example.com',
  'Content-Security-Policy': "frame-ancestors 'self' https://www.example.com;",
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Credentials': true,
  'X-Proxy-Injector': 'gimods Injector',
};

const http_response_headers_delete = [
  'Content-Security-Policy-Report-Only',
  'Clear-Site-Data',
];

const replacement_rules = [
  { search: 'http://{upstream_hostname}/', replace: 'https://{proxy_hostname}/' },
  { search: 'https://{upstream_hostname}/', replace: 'https://{proxy_hostname}/' },
  { search: '//{upstream_hostname}/', replace: '//{proxy_hostname}/' },
  { search: 'http:\\/\\/{upstream_hostname}', replace: 'https:\\/\\/{proxy_hostname}' },
  { search: 'https:\\/\\/{upstream_hostname}', replace: 'https:\\/\\/{proxy_hostname}' },
  { search: '{upstream_hostname}', replace: '{proxy_hostname}' },
];

const replacement_content_types = [
  'text/html',
  'text/css',
  'application/javascript',
  'text/javascript',
  'application/x-javascript',
  'application/json',
];
const default_mirrored_hostnames = ['gimkit.com', 'www.gimkit.com'];

addEventListener('fetch', event => {
  event.respondWith(fetchAndApply(event.request));
});

async function fetchAndApply(request) {
  const regionHeader = request.headers.get('cf-ipcountry');
  const region = regionHeader ? regionHeader.toUpperCase() : null;
  const ipAddress = request.headers.get('cf-connecting-ip');
  const userAgent = request.headers.get('user-agent') || '';

  if (blocked_regions.includes(region) || blocked_ip_addresses.includes(ipAddress)) {
    return new Response('Access denied', { status: 403 });
  }

  const requestUrl = new URL(request.url);
  const proxyHost = requestUrl.host;
  const proxyOrigin = requestUrl.origin;

  const upstreamGET = upstream_allow_override ? requestUrl.searchParams.get(upstream_get_parameter) : null;
  let upstreamDomain;
  if (upstreamGET) {
    upstreamDomain = upstreamGET;
  } else if (upstream_mobile && is_mobile_user_agent(userAgent)) {
    upstreamDomain = upstream_mobile;
  } else {
    upstreamDomain = upstream;
  }

  const upstreamUrl = new URL(requestUrl.href);
  upstreamUrl.protocol = https ? 'https:' : 'http:';
  upstreamUrl.host = upstreamDomain;
  upstreamUrl.pathname = requestUrl.pathname === '/' ? upstream_path : `${upstream_path}${requestUrl.pathname}`;

  const newRequestHeaders = new Headers(request.headers);
  newRequestHeaders.set('Host', upstreamDomain);
  newRequestHeaders.set('Origin', `${upstreamUrl.protocol}//${upstreamDomain}`);
  newRequestHeaders.set('Referer', `${upstreamUrl.protocol}//${upstreamDomain}/`);

  const requestInit = {
    method: request.method,
    headers: newRequestHeaders,
    redirect: 'manual',
  };

  if (!['GET', 'HEAD'].includes(request.method.toUpperCase())) {
    requestInit.body = request.body;
  }

  const upstreamResponse = await fetch(upstreamUrl.toString(), requestInit);

  const connectionUpgrade = newRequestHeaders.get('Upgrade');
  if (connectionUpgrade && connectionUpgrade.toLowerCase() === 'websocket') {
    return upstreamResponse;
  }

  const responseHeaders = new Headers(upstreamResponse.headers);

  for (const [header, value] of Object.entries(http_response_headers_set)) {
    responseHeaders.set(header, value);
  }

  for (const header of http_response_headers_delete) {
    responseHeaders.delete(header);
  }

  rewriteHeaderUrl(responseHeaders, 'x-pjax-url', upstreamUrl, upstreamDomain, proxyHost, proxyOrigin);
  rewriteHeaderUrl(responseHeaders, 'location', upstreamUrl, upstreamDomain, proxyHost, proxyOrigin);

  if (set_cookie_samesite_none && responseHeaders.has('set-cookie')) {
    const firstCookie = responseHeaders.get('set-cookie').split(',').shift();
    responseHeaders.set(
      'set-cookie',
      firstCookie
        .split('SameSite=Lax; Secure').join('')
        .split('SameSite=Lax').join('')
        .split('SameSite=Strict; Secure').join('')
        .split('SameSite=Strict').join('')
        .split('SameSite=None; Secure').join('')
        .split('SameSite=None').join('')
        .replace(/^;+$/g, '') + '; SameSite=None; Secure'
    );
  }

  const responseContentType = (responseHeaders.get('content-type') || '').toLowerCase();
  const shouldRewrite = replacement_content_types.some(v => responseContentType.includes(v));

  if (!shouldRewrite) {
    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
  }

  const originalText = await upstreamResponse.text();
  const rewrittenText = rewriteBodyText(
    originalText,
    upstreamDomain,
    proxyHost,
    proxyOrigin,
    upstreamUrl.toString()
  );

  return new Response(rewrittenText, {
    status: upstreamResponse.status,
    headers: responseHeaders,
  });
}

function rewriteHeaderUrl(headers, headerName, upstreamUrl, upstreamDomain, proxyHost, proxyOrigin) {
  if (!headers.has(headerName)) {
    return;
  }

  const headerValue = headers.get(headerName);
  let rewritten = rewriteAnyUrlString(headerValue, upstreamDomain, proxyHost, proxyOrigin, upstreamUrl.toString());

  if (upstream_allow_override && headerName === 'location') {
    const parsedRaw = safeParseUrl(headerValue, upstreamUrl.toString());
    if (parsedRaw && isExactOrSubdomain(parsedRaw.hostname, 'googleusercontent.com')) {
      rewritten = `${rewritten}&${upstream_get_parameter}=${parsedRaw.hostname}`;
    }
  }

  headers.set(headerName, rewritten);
}

function rewriteBodyText(text, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl) {
  let rewritten = applyReplacementRules(text, upstreamDomain, proxyHost);
  rewritten = rewriteAnyUrlString(rewritten, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl);
  rewritten = rewriteHtmlAttributes(rewritten, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl);
  rewritten = rewriteCssUrls(rewritten, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl);
  rewritten = rewriteScriptRequestLiterals(rewritten, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl);
  return rewritten;
}

function applyReplacementRules(text, upstreamDomain, proxyHost) {
  return replacement_rules.reduce((acc, rule) => {
    const search = rule.search
      .split('{upstream_hostname}').join(upstreamDomain)
      .split('{proxy_hostname}').join(proxyHost);
    const replace = rule.replace
      .split('{upstream_hostname}').join(upstreamDomain)
      .split('{proxy_hostname}').join(proxyHost);

    const regex = new RegExp(escapeRegExp(search), 'g');
    return acc.replace(regex, replace);
  }, text);
}

function rewriteAnyUrlString(text, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl) {
  let rewritten = text;
  const mirroredHosts = getMirroredHosts(upstreamDomain);

  for (const host of mirroredHosts) {
    const escapedHost = escapeRegExp(host);
    rewritten = rewritten.replace(new RegExp(`https?:\\/\\/${escapedHost}`, 'gi'), proxyOrigin);
    rewritten = rewritten.replace(new RegExp(`https?://${escapedHost}`, 'gi'), proxyOrigin);
    rewritten = rewritten.replace(new RegExp(`//${escapedHost}`, 'gi'), `//${proxyHost}`);
  }

  rewritten = rewritten.replace(/(["'`])((?:\/|\.\/|\.\.\/)[^"'`\s]*)\1/g, (match, quote, value) => {
    const proxied = rewriteSingleUrl(value, upstreamDomain, proxyOrigin, baseUpstreamUrl);
    return `${quote}${proxied}${quote}`;
  });

  return rewritten;
}

function rewriteHtmlAttributes(text, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl) {
  const attributePattern = /(href|src|action|poster|data|srcset)=(["'])([^"']*)\2/gi;
  return text.replace(attributePattern, (full, attr, quote, value) => {
    if (attr.toLowerCase() === 'srcset') {
      const rewrittenSrcset = value
        .split(',')
        .map(item => {
          const trimmed = item.trim();
          if (!trimmed) return trimmed;
          const [urlPart, descriptor] = trimmed.split(/\s+/, 2);
          const rewrittenUrl = rewriteSingleUrl(urlPart, upstreamDomain, proxyOrigin, baseUpstreamUrl);
          return descriptor ? `${rewrittenUrl} ${descriptor}` : rewrittenUrl;
        })
        .join(', ');
      return `${attr}=${quote}${rewrittenSrcset}${quote}`;
    }

    const rewritten = rewriteSingleUrl(value, upstreamDomain, proxyOrigin, baseUpstreamUrl);
    return `${attr}=${quote}${rewritten}${quote}`;
  });
}

function rewriteCssUrls(text, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl) {
  return text.replace(/url\((['"]?)([^)'"\s]+)\1\)/gi, (full, quote, value) => {
    const rewritten = rewriteSingleUrl(value, upstreamDomain, proxyOrigin, baseUpstreamUrl);
    const useQuote = quote || '';
    return `url(${useQuote}${rewritten}${useQuote})`;
  });
}

function rewriteScriptRequestLiterals(text, upstreamDomain, proxyHost, proxyOrigin, baseUpstreamUrl) {
  let rewritten = text;

  const patterns = [
    /(fetch\s*\(\s*["'])([^"']+)(["'])/gi,
    /(new\s+Request\s*\(\s*["'])([^"']+)(["'])/gi,
    /(\.open\s*\(\s*["'][A-Za-z]+["']\s*,\s*["'])([^"']+)(["'])/gi,
  ];

  for (const pattern of patterns) {
    rewritten = rewritten.replace(pattern, (full, prefix, value, suffix) => {
      const proxied = rewriteSingleUrl(value, upstreamDomain, proxyOrigin, baseUpstreamUrl);
      return `${prefix}${proxied}${suffix}`;
    });
  }

  return rewritten;
}

function rewriteSingleUrl(value, upstreamDomain, proxyOrigin, baseUpstreamUrl) {
  if (!value) return value;

  const lower = value.toLowerCase();
  if (
    lower.startsWith('javascript:') ||
    lower.startsWith('vbscript:') ||
    lower.startsWith('mailto:') ||
    lower.startsWith('tel:') ||
    lower.startsWith('data:') ||
    lower.startsWith('#')
  ) {
    return value;
  }

  try {
    const parsed = new URL(value, baseUpstreamUrl);
    const proxyOriginUrl = new URL(proxyOrigin);
    const mirroredHosts = getMirroredHosts(upstreamDomain);
    if (mirroredHosts.includes(parsed.hostname)) {
      parsed.protocol = proxyOriginUrl.protocol;
      parsed.host = proxyOriginUrl.host;
      return parsed.toString();
    }

    if (parsed.hostname === proxyOriginUrl.hostname) {
      return parsed.toString();
    }

    if (value.startsWith('/') || value.startsWith('./') || value.startsWith('../')) {
      const proxyUrl = new URL(parsed.pathname + parsed.search + parsed.hash, proxyOrigin);
      return proxyUrl.toString();
    }

    return value;
  } catch (e) {
    return value;
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getMirroredHosts(upstreamDomain) {
  const trimmed = upstreamDomain.replace(/\.$/, '').toLowerCase();
  const base = trimmed.replace(/^www\./, '');
  const hosts = [trimmed, base, `www.${base}`];
  if (isExactOrSubdomain(trimmed, 'gimkit.com')) {
    hosts.push(...default_mirrored_hostnames);
  }
  return Array.from(new Set(hosts));
}

function isExactOrSubdomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function safeParseUrl(value, fallbackBase) {
  try {
    return new URL(value, fallbackBase);
  } catch (e) {
    return null;
  }
}

function is_mobile_user_agent(userAgentInfo) {
  const agents = ['Android', 'iPhone', 'SymbianOS', 'Windows Phone', 'iPad', 'iPod'];
  for (const agent of agents) {
    if (userAgentInfo.includes(agent)) {
      return true;
    }
  }
  return false;
}
