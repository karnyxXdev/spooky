use core::net::SocketAddr;
use std::sync::atomic::AtomicU64;

pub(crate) static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
const FNV_OFFSET_BASIS_64: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME_64: u64 = 0x0000_0100_0000_01b3;

pub fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS_64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    hash
}

pub fn stable_hash_socket_addr(addr: &SocketAddr) -> u64 {
    match addr {
        SocketAddr::V4(v4) => {
            let mut bytes = [0u8; 7];
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&v4.ip().octets());
            bytes[5..7].copy_from_slice(&v4.port().to_be_bytes());
            stable_hash64(&bytes)
        }
        SocketAddr::V6(v6) => {
            let mut bytes = [0u8; 31];
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&v6.ip().octets());
            bytes[17..19].copy_from_slice(&v6.port().to_be_bytes());
            bytes[19..23].copy_from_slice(&v6.flowinfo().to_be_bytes());
            bytes[23..27].copy_from_slice(&v6.scope_id().to_be_bytes());
            stable_hash64(&bytes)
        }
    }
}
