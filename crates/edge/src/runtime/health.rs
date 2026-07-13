#[derive(Debug)]
pub enum HealthClassification {
    Success, // 2xx, 3xx responses
    Failure, // 5xx responses, Transport/Pool/Timeout errors
    Neutral, // 4xx responses, Bridge/TLS errors
}

pub fn outcome_from_status(status: http::StatusCode) -> HealthClassification {
    if status.is_server_error() {
        // 5xx
        HealthClassification::Failure
    } else if status.is_client_error() {
        // 4xx
        HealthClassification::Neutral
    } else {
        // 2xx, 3xx
        HealthClassification::Success
    }
}
