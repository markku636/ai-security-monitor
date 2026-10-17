//! Hub 身分（Ed25519）：`GET /api/v1/hub/identity?nonce=…` 回傳公鑰、指紋與對 nonce 的簽章。
//!
//! - 指紋＝SHA-256(公鑰 32 bytes) 的 base32（RFC 4648、無補位）前 20 字，每 4 字一組：`72AS-YEXT-VNGO-NLC5-W2NM`。
//! - agent 第一次加入時釘選指紋（TOFU），之後同一個或自動找到的網址回報不同身分就拒絕，除非使用者明確重新加入。
//! - 驗章訊息：`asa-hub-identity|v1|<nonce>|<fingerprint>`；核准結果：`asa-enroll-approved|v1|<request_id>|<agent_id>|<sha256hex(client_key)>`。
//!
//! 格式與 `contract/hub-identity.v1.json`、`contract/enroll-status.v1.json` 一致（兩邊都有測試）。

use std::time::Duration;

use base64::Engine;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};

pub const IDENTITY_PATH: &str = "/api/v1/hub/identity";

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct EnrollmentInfo {
    /// Hub 是否接受免金鑰的加入申請。
    pub keyless: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct HubIdentity {
    pub name: String,
    pub version: String,
    pub edition: String,
    pub algorithm: String,
    /// Ed25519 公鑰（32 bytes，base64url）。
    pub public_key: String,
    pub fingerprint: String,
    pub enrollment: EnrollmentInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32，不補 `=`。
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((acc >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn grouped(s: &str, groups: usize) -> String {
    s.as_bytes()
        .chunks(4)
        .take(groups)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// 公鑰的指紋（20 個 base32 字元＝100 bits）。
pub fn fingerprint_of(public_key: &[u8]) -> String {
    grouped(&base32(&Sha256::digest(public_key)), 5)
}

/// 加入申請的核對碼（電腦端與 Hub 管理頁顯示同一組，讓管理員確認是哪一台）。
pub fn request_code(secret: &str) -> String {
    grouped(&base32(&Sha256::digest(format!("asa-enroll-code|{secret}"))), 2)
}

/// 指紋比對：大小寫與分隔符號不影響。
pub fn same_fingerprint(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>()
    };
    let (x, y) = (norm(a), norm(b));
    !x.is_empty() && x == y
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim().trim_end_matches('='))
        .ok()
}

pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 安全亂數（作業系統 CSPRNG）。
pub fn random_bytes<const N: usize>() -> AppResult<[u8; N]> {
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| AppError::Hub("random number generator failed".into()))?;
    Ok(b)
}

/// 驗 Ed25519 簽章（公鑰與簽章都是 base64url）。
pub fn verify_signature(public_key_b64: &str, message: &str, signature_b64: &str) -> bool {
    let (Some(pk), Some(sig)) = (b64url_decode(public_key_b64), b64url_decode(signature_b64)) else {
        return false;
    };
    if pk.len() != 32 || sig.len() != 64 {
        return false;
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk)
        .verify(message.as_bytes(), &sig)
        .is_ok()
}

impl HubIdentity {
    /// 驗證：Ed25519、指紋＝公鑰的指紋、nonce 是我們給的、簽章正確。
    pub fn verify(&self, nonce: &str) -> AppResult<()> {
        if !self.algorithm.eq_ignore_ascii_case("ed25519") {
            return Err(AppError::HubIdentity(tf!(
                "Hub 身分使用不支援的演算法：{alg}",
                alg = self.algorithm
            )));
        }
        let pk = b64url_decode(&self.public_key)
            .filter(|k| k.len() == 32)
            .ok_or_else(|| AppError::HubIdentity(t!("Hub 身分的公鑰格式錯誤").into()))?;
        if fingerprint_of(&pk) != self.fingerprint {
            return Err(AppError::HubIdentity(t!("Hub 身分的指紋與公鑰不符").into()));
        }
        if self.nonce.as_deref() != Some(nonce) {
            return Err(AppError::HubIdentity(
                t!("Hub 身分回應不是針對這次的查詢（nonce 不符）").into(),
            ));
        }
        let msg = format!("asa-hub-identity|v1|{nonce}|{}", self.fingerprint);
        if !verify_signature(&self.public_key, &msg, self.signature.as_deref().unwrap_or("")) {
            return Err(AppError::HubIdentity(t!("Hub 身分的簽章驗證失敗").into()));
        }
        Ok(())
    }
}

pub fn new_nonce() -> AppResult<String> {
    Ok(b64url(&random_bytes::<18>()?))
}

pub fn http_client(timeout: Duration) -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("ai-security-monitor/{}", crate::VERSION))
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
        .build()
        .map_err(|e| AppError::Hub(e.to_string()))
}

/// 查 Hub 身分並驗章；舊版 Hub 沒有這個端點（404）回 `Ok(None)`。
pub async fn fetch(http: &reqwest::Client, base: &str) -> AppResult<Option<HubIdentity>> {
    let nonce = new_nonce()?;
    let url = format!("{}{IDENTITY_PATH}?nonce={nonce}", base.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::Hub(tf!("連不上 hub：{e}", e = e)))?;
    let status = resp.status().as_u16();
    if status == 404 {
        return Ok(None);
    }
    if status != 200 {
        return Err(AppError::Hub(tf!(
            "查詢 Hub 身分失敗（HTTP {status}）",
            status = status
        )));
    }
    let id: HubIdentity = resp
        .json()
        .await
        .map_err(|_| AppError::HubIdentity(t!("這個網址不是 Security Hub（身分回應格式不對）").into()))?;
    id.verify(&nonce)?;
    Ok(Some(id))
}

/// 和釘選的指紋比對。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    /// 還沒釘選（第一次加入）。
    Unpinned,
    Same,
    Mismatch {
        pinned: String,
        seen: String,
    },
}

pub fn check_pin(pinned: Option<&str>, seen: &str) -> PinCheck {
    match pinned.filter(|p| !p.trim().is_empty()) {
        None => PinCheck::Unpinned,
        Some(p) if same_fingerprint(p, seen) => PinCheck::Same,
        Some(p) => PinCheck::Mismatch {
            pinned: p.to_string(),
            seen: seen.to_string(),
        },
    }
}

/// 指紋不同時給使用者看的說明。
pub fn mismatch_message(pinned: &str, seen: &str) -> String {
    tf!(
        "Hub 的身分指紋變了：這台電腦記得的是 {pinned}，現在這個 Hub 是 {seen}。可能是 Hub 重新安裝，也可能有人冒充公司的 Hub。請向管理員確認指紋；確定要改加入新的 Hub 請執行 ai-security-monitor enroll --auto --repin",
        pinned = pinned,
        seen = seen
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(name: &str) -> serde_json::Value {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../contract")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(base32(b"foob"), "MZXW6YQ");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn contract_identity_verifies_and_tampering_fails() {
        let v = contract("hub-identity.v1.json");
        let id: HubIdentity = serde_json::from_value(v).unwrap();
        let nonce = id.nonce.clone().unwrap();
        id.verify(&nonce).unwrap();
        assert_eq!(
            fingerprint_of(&b64url_decode(&id.public_key).unwrap()),
            "72AS-YEXT-VNGO-NLC5-W2NM"
        );
        assert!(id.enrollment.keyless);
        // 別的 nonce（重放）、改指紋、改簽章都要失敗
        assert!(id.verify("another-nonce-123456").is_err());
        let mut bad = id.clone();
        bad.fingerprint = "AAAA-BBBB-CCCC-DDDD-EEEE".into();
        assert!(bad.verify(&nonce).is_err());
        let mut bad = id.clone();
        let mut sig = b64url_decode(bad.signature.as_deref().unwrap()).unwrap();
        sig[0] ^= 1;
        bad.signature = Some(b64url(&sig));
        assert!(bad.verify(&nonce).is_err());
        let mut bad = id;
        bad.algorithm = "rsa".into();
        assert!(bad.verify(&nonce).is_err());
    }

    #[test]
    fn request_code_matches_contract() {
        let req = contract("enroll-request.v1.json");
        let st = contract("enroll-status.v1.json");
        assert_eq!(
            request_code(req["request_secret"].as_str().unwrap()),
            st["request_code"].as_str().unwrap()
        );
        assert_eq!(request_code(req["request_secret"].as_str().unwrap()), "ENDY-Z24W");
    }

    #[test]
    fn pin_checks_ignore_case_and_dashes() {
        assert_eq!(check_pin(None, "AAAA-BBBB"), PinCheck::Unpinned);
        assert_eq!(check_pin(Some(""), "AAAA-BBBB"), PinCheck::Unpinned);
        assert_eq!(check_pin(Some("aaaabbbb"), "AAAA-BBBB"), PinCheck::Same);
        assert!(matches!(
            check_pin(Some("AAAA-BBBC"), "AAAA-BBBB"),
            PinCheck::Mismatch { .. }
        ));
        assert!(!same_fingerprint("", ""));
    }

    #[test]
    fn random_values_differ() {
        assert_ne!(new_nonce().unwrap(), new_nonce().unwrap());
        assert_eq!(new_nonce().unwrap().len(), 24);
    }

    #[tokio::test]
    async fn fetch_verifies_and_treats_404_as_old_hub() {
        // 簽章是對固定 nonce 做的：回應裡的 nonce 不是這次產生的 → 必須拒絕（防重放）
        let body = contract("hub-identity.v1.json").to_string();
        let (url, _) = crate::hub::test_server::serve(vec![(200, body), (404, "{}".into())]).await;
        let http = http_client(Duration::from_secs(5)).unwrap();
        let e = fetch(&http, &url).await.unwrap_err();
        assert!(e.message().contains("nonce"), "{}", e.message());
        assert_eq!(fetch(&http, &url).await.unwrap(), None);
    }
}
