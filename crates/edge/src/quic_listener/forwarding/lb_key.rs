use super::*;

fn extract_cookie_value(cookie_header: &str, cookie_name: &str) -> Option<String> {
    for pair in cookie_header.split(';') {
        let part = pair.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part.split_once('=')?;
        if name.trim().eq_ignore_ascii_case(cookie_name) {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

fn extract_query_param(path: &str, param: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    for pair in query.split('&') {
        let entry = pair.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, value) = entry.split_once('=')?;
        if name.eq_ignore_ascii_case(param) && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

impl QUICListener {
    pub(super) fn resolve_lb_key_from_spec(
        lb_key_spec: &str,
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        client_addr: Option<SocketAddr>,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Option<String> {
        let spec = lb_key_spec.trim();
        if spec.is_empty() {
            return None;
        }

        if spec.eq_ignore_ascii_case("path") {
            let path_only = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
            return Some(path_only.to_string());
        }
        if spec.eq_ignore_ascii_case("authority") {
            return authority.map(str::to_string);
        }
        if spec.eq_ignore_ascii_case("method") {
            return Some(method.to_string());
        }
        if spec.eq_ignore_ascii_case("cid") || spec.eq_ignore_ascii_case("sticky-cid") {
            return cid_key.map(str::to_string);
        }
        if spec.eq_ignore_ascii_case("peer_ip") || spec.eq_ignore_ascii_case("client_ip") {
            return client_addr.map(|addr| addr.ip().to_string());
        }
        if spec.eq_ignore_ascii_case("bearer_token") {
            let raw =
                header_lookup.and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str()))?;
            return Self::bearer_token_from_authorization_value(&raw);
        }

        let (source, key_name) = spec.split_once(':')?;
        let key_name = key_name.trim();
        if key_name.is_empty() {
            return None;
        }

        if source.eq_ignore_ascii_case("header") {
            return header_lookup.and_then(|lookup| lookup(key_name));
        }

        if source.eq_ignore_ascii_case("cookie") {
            let cookie_header =
                header_lookup.and_then(|lookup| lookup(http::header::COOKIE.as_str()))?;
            return extract_cookie_value(cookie_header.as_str(), key_name);
        }

        if source.eq_ignore_ascii_case("query") {
            return extract_query_param(path, key_name);
        }

        None
    }

    pub(super) fn default_lb_request_key(
        method: &str,
        path: &str,
        authority: Option<&str>,
    ) -> String {
        authority
            .unwrap_or(if !path.is_empty() { path } else { method })
            .to_string()
    }

    pub(super) fn resolve_lb_request_key(
        lb_type: &str,
        lb_key_spec: Option<&str>,
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> String {
        let default_key = Self::default_lb_request_key(method, path, authority);

        if let Some(spec) = lb_key_spec
            && let Some(value) = Self::resolve_lb_key_from_spec(
                spec,
                method,
                path,
                authority,
                cid_key,
                None,
                header_lookup,
            )
            && !value.is_empty()
        {
            return value;
        }

        if lb_type == "sticky-cid"
            && let Some(cid_key) = cid_key
        {
            return cid_key.to_string();
        }

        default_key
    }

    pub(super) fn bearer_token_from_authorization_value(raw: &str) -> Option<String> {
        let raw = raw.trim();
        let split = raw.find(char::is_whitespace)?;
        let (scheme, rest) = raw.split_at(split);
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = rest.trim_start();
        if token.is_empty() {
            return None;
        }
        Some(token.to_string())
    }
}
