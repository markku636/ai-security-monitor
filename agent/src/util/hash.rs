use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::AppResult;

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// 檔案 sha256（串流讀取，不整檔載入）。
pub fn sha256_file(path: &Path) -> AppResult<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// 穩定 id：`<prefix>_` + sha256(`v1|part1|part2|…`) 前 16 個 hex。
/// 帶版本前綴，日後 evidence key 規則改變時升 `v2`。
pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut joined = String::from("v1");
    for p in parts {
        joined.push('|');
        joined.push_str(p);
    }
    let h = sha256_hex(joined.as_bytes());
    format!("{prefix}_{}", &h[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_id_is_deterministic_and_order_sensitive() {
        let a = stable_id("f", &["connections", "risky_port", "1.2.3.4:4444"]);
        let b = stable_id("f", &["connections", "risky_port", "1.2.3.4:4444"]);
        let c = stable_id("f", &["connections", "risky_port", "1.2.3.4:4445"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("f_") && a.len() == 18);
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
