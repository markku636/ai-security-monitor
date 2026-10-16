//! Windows kernel dump（Minidump\*.dmp、MEMORY.DMP）檔頭：只讀前 0x60 bytes 取 bugcheck 代碼與四個參數。
//! 64 位元：`PAGE` + `DU64`，代碼在 0x38、參數在 0x40..0x60；32 位元：`PAGE` + `DUMP`，代碼在 0x20、參數在 0x24..0x34。

use std::io::Read;
use std::path::Path;

use chrono::{DateTime, Utc};

use super::catalog;
use super::model::CrashRecord;

#[derive(Debug, Clone, PartialEq)]
pub struct DumpHeader {
    pub bits: u8,
    pub code: u32,
    pub params: [u64; 4],
}

pub fn parse_header(b: &[u8]) -> Option<DumpHeader> {
    if b.len() < 0x60 || &b[0..4] != b"PAGE" {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    match &b[4..8] {
        b"DU64" => Some(DumpHeader {
            bits: 64,
            code: u32_at(0x38),
            params: [u64_at(0x40), u64_at(0x48), u64_at(0x50), u64_at(0x58)],
        }),
        b"DUMP" => Some(DumpHeader {
            bits: 32,
            code: u32_at(0x20),
            params: [
                u32_at(0x24) as u64,
                u32_at(0x28) as u64,
                u32_at(0x2C) as u64,
                u32_at(0x30) as u64,
            ],
        }),
        _ => None,
    }
}

pub fn read_header(path: &Path) -> std::io::Result<Option<DumpHeader>> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 0x60];
    let n = f.read(&mut buf)?;
    Ok(parse_header(&buf[..n]))
}

pub fn to_crash(h: &DumpHeader, time: DateTime<Utc>, path: &Path) -> CrashRecord {
    let mut c = CrashRecord::new("bugcheck", time, format!("minidump:{}", path.display()));
    c.code = Some(catalog::code_hex(h.code));
    c.params = h.params.iter().map(|p| format!("0x{p:x}")).collect();
    if let Some(b) = catalog::lookup_bugcheck(h.code) {
        let (causes, fix) = catalog::bugcheck_text(&b);
        c.name = Some(b.name);
        c.likely_causes = causes;
        c.remediation = Some(fix);
    }
    c
}

#[cfg(test)]
pub(crate) fn sample64(code: u32, p1: u64) -> Vec<u8> {
    let mut b = vec![0u8; 0x80];
    b[0..4].copy_from_slice(b"PAGE");
    b[4..8].copy_from_slice(b"DU64");
    b[0x38..0x3C].copy_from_slice(&code.to_le_bytes());
    b[0x40..0x48].copy_from_slice(&p1.to_le_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_64_and_32_bit_headers() {
        let h = parse_header(&sample64(0x7E, 0xffff_ffff_c000_0005)).unwrap();
        assert_eq!((h.bits, h.code, h.params[0]), (64, 0x7E, 0xffff_ffff_c000_0005));
        let mut b = vec![0u8; 0x60];
        b[0..8].copy_from_slice(b"PAGEDUMP");
        b[0x20..0x24].copy_from_slice(&0xD1u32.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&7u32.to_le_bytes());
        let h = parse_header(&b).unwrap();
        assert_eq!((h.bits, h.code, h.params[0]), (32, 0xD1, 7));
        assert!(parse_header(b"MDMP and more bytes").is_none());
        assert!(parse_header(&[0u8; 10]).is_none());
    }

    #[test]
    fn reads_file_and_explains() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("101626-12345-01.dmp");
        std::fs::write(&p, sample64(0x124, 0)).unwrap();
        let h = read_header(&p).unwrap().unwrap();
        let c = to_crash(&h, Utc::now(), &p);
        assert_eq!(c.code.as_deref(), Some("0x00000124"));
        assert_eq!(c.name.as_deref(), Some("WHEA_UNCORRECTABLE_ERROR"));
        assert!(!c.likely_causes.is_empty() && c.remediation.is_some());
    }
}
