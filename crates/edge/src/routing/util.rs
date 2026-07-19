#[inline(always)]
pub fn prefix_boundary_matches(path: &str, prefix_len: usize) -> bool {
    if prefix_len <= 1 {
        return true;
    }
    if path.len() == prefix_len {
        return true;
    }
    path.as_bytes().get(prefix_len) == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::prefix_boundary_matches;

    #[test]
    fn prefix_boundary_matches_exact_prefix_length() {
        assert!(prefix_boundary_matches("/api", "/api".len()));
    }

    #[test]
    fn prefix_boundary_matches_segment_boundary() {
        assert!(prefix_boundary_matches("/api/v1", "/api".len()));
    }

    #[test]
    fn prefix_boundary_rejects_mid_segment_match() {
        assert!(!prefix_boundary_matches("/apixyz", "/api".len()));
    }

    #[test]
    fn prefix_boundary_treats_root_prefix_as_match() {
        assert!(prefix_boundary_matches("/anything", 1));
    }
}
