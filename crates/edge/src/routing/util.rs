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
