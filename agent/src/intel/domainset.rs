//! DomainSet：大量網域的精簡集合。每個網域只存 64-bit 雜湊（排序後二分搜尋），
//! 有附加資訊的條目才帶一個 meta 索引。50 萬筆約 6 MB（存字串要幾十 MB）。
//! 比對：雜湊高位元先查分桶索引（每桶約 16–32 筆），再在桶內二分搜尋，200 萬筆時每層只碰幾條 cache line。
//! 碰撞機率：100 萬筆時任一查詢誤中約 5e-14，可忽略。

/// 沒有附加資訊的條目。
pub const NO_META: u32 = u32::MAX;

/// 網域雜湊：FNV-1a 64，先轉小寫、去掉結尾的點，最後再混一次（高位元拿來分桶，要分布均勻）。
/// 同一份程式內穩定即可（不落地）。
pub fn hash(name: &str) -> u64 {
    let n = name.strip_suffix('.').unwrap_or(name);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in n.bytes() {
        h ^= u64::from(b.to_ascii_lowercase());
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // MurmurHash3 fmix64
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^ (h >> 33)
}

#[derive(Debug, Default, Clone)]
pub struct DomainSet {
    hashes: Vec<u64>,
    metas: Vec<u32>,
    /// 分桶索引：桶 b 的條目在 `hashes[index[b]..index[b + 1]]`；條目少時是空的（直接二分搜尋）。
    index: Vec<u32>,
    shift: u32,
}

/// 幾個位元分桶：每桶平均 16–32 筆，最多 2^20 桶；1,024 筆以下不分桶。
fn bucket_bits(n: usize) -> u32 {
    if n < 1024 {
        return 0;
    }
    (usize::BITS - n.leading_zeros()).saturating_sub(5).min(20)
}

/// 命中：比中的那一層網域（可能是查詢名稱的上層）與 meta 索引（`NO_META`＝沒有附加資訊）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainHit<'a> {
    pub matched: &'a str,
    pub meta: u32,
}

impl DomainSet {
    /// 由 (雜湊, meta) 建立；重複的雜湊保留第一筆。
    pub fn build(mut entries: Vec<(u64, u32)>) -> DomainSet {
        entries.sort_unstable_by_key(|e| e.0);
        entries.dedup_by_key(|e| e.0);
        let (hashes, metas): (Vec<u64>, Vec<u32>) = entries.into_iter().unzip();
        let bits = bucket_bits(hashes.len());
        if bits == 0 {
            return DomainSet {
                hashes,
                metas,
                index: Vec::new(),
                shift: 0,
            };
        }
        let shift = 64 - bits;
        let mut index = vec![0u32; (1usize << bits) + 1];
        for h in &hashes {
            index[(h >> shift) as usize + 1] += 1;
        }
        for i in 1..index.len() {
            index[i] += index[i - 1];
        }
        DomainSet {
            hashes,
            metas,
            index,
            shift,
        }
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    fn find(&self, h: u64) -> Option<u32> {
        if self.index.is_empty() {
            return self.hashes.binary_search(&h).ok().map(|i| self.metas[i]);
        }
        let b = (h >> self.shift) as usize;
        let (lo, hi) = (self.index[b] as usize, self.index[b + 1] as usize);
        self.hashes[lo..hi].binary_search(&h).ok().map(|i| self.metas[lo + i])
    }

    /// `subdomains`＝true：名稱本身或任一上層（不含單獨的頂級網域）在集合內就算命中；false：只比完全相同。
    pub fn lookup<'a>(&self, name: &'a str, subdomains: bool) -> Option<DomainHit<'a>> {
        let mut cur = name.strip_suffix('.').unwrap_or(name);
        loop {
            if let Some(meta) = self.find(hash(cur)) {
                return Some(DomainHit { matched: cur, meta });
            }
            if !subdomains {
                return None;
            }
            match cur.split_once('.') {
                Some((_, rest)) if rest.contains('.') => cur = rest,
                _ => return None,
            }
        }
    }

    /// 估計佔用的記憶體（bytes）。
    pub fn heap_bytes(&self) -> usize {
        self.hashes.capacity() * 8 + self.metas.capacity() * 4 + self.index.capacity() * 4
    }
}

/// 檢查並正規化網域：小寫、去結尾點；只收 ASCII 字母數字、`-`、`_`，至少兩段、總長 ≤ 253、每段 ≤ 63。
pub fn normalize(raw: &str) -> Option<String> {
    let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 || !d.contains('.') {
        return None;
    }
    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> DomainSet {
        DomainSet::build(names.iter().enumerate().map(|(i, n)| (hash(n), i as u32)).collect())
    }

    #[test]
    fn bucketed_set_finds_every_entry() {
        let names: Vec<String> = (0..50_000).map(|i| format!("n{i}.bucket.example")).collect();
        let s = DomainSet::build(names.iter().enumerate().map(|(i, n)| (hash(n), i as u32)).collect());
        assert!(!s.index.is_empty());
        for (i, n) in names.iter().enumerate().step_by(97) {
            assert_eq!(s.lookup(&format!("www.{n}"), true).map(|h| h.meta), Some(i as u32));
        }
        assert!(s.lookup("absent.bucket.example", true).is_none());
        assert_eq!(bucket_bits(2_000_000), 16);
        assert_eq!(bucket_bits(1000), 0);
    }

    #[test]
    fn hash_ignores_case_and_trailing_dot() {
        assert_eq!(hash("Evil.Example."), hash("evil.example"));
        assert_ne!(hash("evil.example"), hash("evil.example2"));
    }

    #[test]
    fn suffix_and_exact_lookup() {
        let s = set(&["evil.example", "bad.test"]);
        let h = s.lookup("a.b.evil.example", true).unwrap();
        assert_eq!(h.matched, "evil.example");
        assert_eq!(h.meta, 0);
        assert!(s.lookup("a.b.evil.example", false).is_none());
        assert_eq!(s.lookup("BAD.test.", false).unwrap().meta, 1);
        assert!(s.lookup("example", true).is_none());
        assert!(s.lookup("notevil.example", true).is_none());
    }

    #[test]
    fn duplicates_keep_first() {
        let s = DomainSet::build(vec![(hash("x.test"), 3), (hash("x.test"), 9)]);
        assert_eq!(s.len(), 1);
        assert_eq!(s.lookup("x.test", true).unwrap().meta, 3);
    }

    #[test]
    fn normalize_rejects_garbage() {
        assert_eq!(normalize(" Evil.Example. ").as_deref(), Some("evil.example"));
        assert!(normalize("localhost").is_none());
        assert!(normalize("bad domain.test").is_none());
        assert!(normalize("a..b").is_none());
        assert!(normalize("ex\u{e4}mple.test").is_none());
        assert!(normalize(&format!("{}.test", "a".repeat(64))).is_none());
    }
}
