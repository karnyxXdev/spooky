use crate::cli::BenchSuite;

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn suite_label(suite: BenchSuite) -> &'static str {
    match suite {
        BenchSuite::Micro => "micro",
        BenchSuite::Macro => "macro",
        BenchSuite::All => "all",
    }
}

pub fn default_true() -> bool {
    true
}

pub fn default_macro_traffic_mix_iterations() -> u64 {
    20_000
}

pub fn default_macro_stream_iterations() -> u64 {
    8_000
}

pub fn default_macro_stream_chunks() -> usize {
    64
}

pub fn default_macro_stream_chunk_bytes() -> usize {
    8 * 1024
}
