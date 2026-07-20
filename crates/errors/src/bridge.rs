use thiserror::Error;
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("invalid HTTP method")]
    InvalidMethod,

    #[error("invalid URI")]
    InvalidUri,

    #[error("invalid header")]
    InvalidHeader,

    #[error("failed to build request: {0}")]
    Build(#[from] http::Error),
}

#[cfg(test)]
mod tests {
    use super::BridgeError;

    fn invalid_build_error() -> http::Error {
        http::Request::builder()
            .header("bad\nname", "value")
            .body(())
            .expect_err("invalid header name should fail request build")
    }

    #[test]
    fn display_covers_simple_bridge_variants() {
        assert_eq!(
            BridgeError::InvalidMethod.to_string(),
            "invalid HTTP method"
        );
        assert_eq!(BridgeError::InvalidUri.to_string(), "invalid URI");
        assert_eq!(BridgeError::InvalidHeader.to_string(), "invalid header");
    }

    #[test]
    fn build_variant_display_includes_http_error() {
        let error = BridgeError::Build(invalid_build_error());

        assert!(error.to_string().starts_with("failed to build request: "));
    }
}
