pub fn normalize_connect_authority(authority: &str) -> Option<String> {
    let trimmed = authority.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        if host.is_empty() {
            return None;
        }
        let suffix = &rest[end + 1..];
        if !suffix.starts_with(':') || suffix.len() <= 1 {
            return None;
        }
        let port = suffix[1..].parse::<u16>().ok().filter(|value| *value > 0)?;
        return Some(format!(
            "[{}]:{}",
            host.trim_end_matches('.').to_ascii_lowercase(),
            port
        ));
    }

    let (host, port) = trimmed.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    let port = port.parse::<u16>().ok().filter(|value| *value > 0)?;
    Some(format!(
        "{}:{}",
        host.trim_end_matches('.').to_ascii_lowercase(),
        port
    ))
}

pub fn connect_authority_port(normalized_authority: &str) -> Option<u16> {
    if normalized_authority.starts_with('[') {
        let end = normalized_authority.find(']')?;
        let suffix = normalized_authority.get(end + 1..)?;
        return suffix.strip_prefix(':')?.parse::<u16>().ok();
    }
    normalized_authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}
