#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthFailureReason {
    HttpStatus5xx,
    Timeout,
    Transport,
    Tls,
    CircuitOpen,
}
