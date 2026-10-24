//! 擁有權驗證（verify 工作）：runner 自己發一個 HTTP GET 找 Hub 給的 token。
//!
//! - `well-known`：`{scheme}://{host}:{port}/.well-known/asm-verify.txt`，body ≤ 4 KiB，內容（trim）包含 token 就算找到。
//! - `meta`：目標網址，body ≤ 512 KiB，找 `<meta name="asm-verify" content="<token>">`（屬性順序、引號、大小寫寬鬆）。
//!
//! 只連釘選位址（reqwest `resolve_to_addrs`）、不走代理、不跟轉址、逾時 15 秒；https 接受無效憑證（只是找 token）。

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;

use super::job::{Verify, VerifyMethod};
use super::scope::Target;
use super::{clean_detail, VerifyResult};

pub const WELL_KNOWN_PATH: &str = "/.well-known/asm-verify.txt";
const WELL_KNOWN_MAX: usize = 4 * 1024;
const META_MAX: usize = 512 * 1024;
/// 預設逾時。
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// 驗證的結果；`responded`＝有拿到 HTTP 回應（不論狀態碼）。
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub responded: bool,
    pub result: VerifyResult,
}

/// 只連釘選位址的 HTTP client（目標本身是 IP 時不需要覆寫解析）。
pub fn client(target: &Target, timeout: Duration) -> reqwest::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(format!("ai-security-monitor-webscan/{}", crate::VERSION))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout);
    if target.host_ip.is_none() {
        let addrs: Vec<SocketAddr> = target
            .pinned
            .iter()
            .map(|ip| SocketAddr::new(*ip, target.port))
            .collect();
        b = b.resolve_to_addrs(&target.host, &addrs);
    }
    b.build()
}

/// 讀 body，最多 `cap` bytes（多的不下載）。
async fn read_capped(mut resp: reqwest::Response, cap: usize) -> reqwest::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        let room = cap.saturating_sub(out.len());
        out.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if out.len() >= cap {
            break;
        }
    }
    Ok(out)
}

/// 連線錯誤的簡短說明（送回 Hub，只留可見 ASCII）。
fn describe(e: &reqwest::Error) -> String {
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect_error"
    } else if e.is_body() || e.is_decode() {
        "body_error"
    } else {
        "request_error"
    };
    let mut root: &dyn std::error::Error = e;
    while let Some(next) = root.source() {
        root = next;
    }
    format!("{kind}: {}", clean_detail(&root.to_string(), 120))
}

/// `<meta name="asm-verify" content="…">`：屬性順序不拘，單引號、雙引號、不加引號都可以，名稱不分大小寫。
pub fn meta_has_token(html: &str, token: &str) -> bool {
    static TAG: OnceLock<Regex> = OnceLock::new();
    static ATTR: OnceLock<Regex> = OnceLock::new();
    let tag = TAG.get_or_init(|| Regex::new(r"(?is)<meta\b([^>]*)>").expect("valid regex"));
    let attr = ATTR.get_or_init(|| {
        Regex::new(r#"(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#).expect("valid regex")
    });
    for t in tag.captures_iter(html) {
        let mut name = None;
        let mut content = None;
        for a in attr.captures_iter(&t[1]) {
            let value = a
                .get(2)
                .or_else(|| a.get(3))
                .or_else(|| a.get(4))
                .map(|m| m.as_str().trim())
                .unwrap_or_default();
            match a[1].to_ascii_lowercase().as_str() {
                "name" => name = Some(value),
                "content" => content = Some(value),
                _ => {}
            }
        }
        if name.is_some_and(|n| n.eq_ignore_ascii_case("asm-verify")) && content == Some(token) {
            return true;
        }
    }
    false
}

/// 做一次擁有權驗證。
pub async fn check(target: &Target, v: &Verify, timeout: Duration) -> Outcome {
    let no_response = |detail: String| Outcome {
        responded: false,
        result: VerifyResult {
            found: false,
            http_status: None,
            detail,
        },
    };
    let (url, cap) = match v.method {
        VerifyMethod::WellKnown => (target.url_with_path(WELL_KNOWN_PATH), WELL_KNOWN_MAX),
        VerifyMethod::Meta => (target.url(), META_MAX),
    };
    let client = match client(target, timeout) {
        Ok(c) => c,
        Err(e) => return no_response(describe(&e)),
    };
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return no_response(describe(&e)),
    };
    let status = resp.status();
    let (found, detail) = match read_capped(resp, cap).await {
        Ok(body) if status.is_success() => {
            let text = String::from_utf8_lossy(&body);
            let found = match v.method {
                VerifyMethod::WellKnown => text.trim().contains(v.token.as_str()),
                VerifyMethod::Meta => meta_has_token(&text, &v.token),
            };
            (found, if found { "found" } else { "token_not_found" }.to_string())
        }
        Ok(_) => (false, "http_status".to_string()),
        Err(e) => (false, describe(&e)),
    };
    Outcome {
        responded: true,
        result: VerifyResult {
            found,
            http_status: Some(status.as_u16()),
            detail,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webscan::scope::Scheme;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TOKEN: &str = "asm-verify-6f1c2b9a0d4e8f7a6b5c4d3e2f1a0b9c";

    /// 127.0.0.1 上的小 HTTP 伺服器：依序回固定的回應，交回收到的請求開頭。
    async fn serve(responses: Vec<String>) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let mut heads = Vec::new();
            for resp in responses {
                let Ok((mut s, _)) = l.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                heads.push(String::from_utf8_lossy(&got).to_string());
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            }
            heads
        });
        (port, h)
    }

    fn http(status: &str, extra: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n{body}",
            body.len()
        )
    }

    /// 名稱解析不到（.test）的目標，釘到 127.0.0.1：連得到就代表 resolve 覆寫有效。
    fn target(port: u16, path: &str) -> Target {
        Target {
            scheme: Scheme::Http,
            host: "shop.example.test".into(),
            host_ip: None,
            port,
            path: path.into(),
            pinned: vec![IpAddr::from([127, 0, 0, 1])],
            names: vec!["shop.example.test".into()],
            internal: false,
        }
    }

    fn verify(method: VerifyMethod) -> Verify {
        Verify {
            method,
            token: TOKEN.into(),
        }
    }

    #[tokio::test]
    async fn well_known_token_over_the_pinned_address() {
        let (port, h) = serve(vec![
            http("200 OK", "", &format!("  {TOKEN}\n")),
            http("200 OK", "", "something-else"),
            http("404 Not Found", "", TOKEN),
        ])
        .await;
        let t = target(port, "/");
        let v = verify(VerifyMethod::WellKnown);
        let o = check(&t, &v, TIMEOUT).await;
        assert!(o.responded);
        assert_eq!(
            o.result,
            VerifyResult {
                found: true,
                http_status: Some(200),
                detail: "found".into()
            }
        );
        let o = check(&t, &v, TIMEOUT).await;
        assert_eq!((o.result.found, o.result.detail.as_str()), (false, "token_not_found"));
        let o = check(&t, &v, TIMEOUT).await;
        assert_eq!(
            (o.result.found, o.result.http_status, o.result.detail.as_str()),
            (false, Some(404), "http_status")
        );
        let heads = h.await.unwrap();
        assert!(
            heads[0].starts_with("GET /.well-known/asm-verify.txt HTTP/1.1\r\n"),
            "{}",
            heads[0]
        );
        let lower = heads[0].to_ascii_lowercase();
        assert!(
            lower.contains(&format!("host: shop.example.test:{port}")),
            "{}",
            heads[0]
        );
        assert!(lower.contains("user-agent: ai-security-monitor-webscan/"));
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let (port, h) = serve(vec![http(
            "302 Found",
            "location: http://127.0.0.1:1/.well-known/asm-verify.txt\r\n",
            "",
        )])
        .await;
        let o = check(&target(port, "/"), &verify(VerifyMethod::WellKnown), TIMEOUT).await;
        assert!(o.responded && !o.result.found);
        assert_eq!(o.result.http_status, Some(302));
        assert_eq!(h.await.unwrap().len(), 1, "only one request");
    }

    #[tokio::test]
    async fn meta_tag_on_the_target_page_and_size_cap() {
        let page = format!(
            "<!doctype html><html><head><title>x</title><META CONTENT='{TOKEN}' Name=ASM-VERIFY></head></html>"
        );
        let mut big = "x".repeat(META_MAX + 10);
        big.push_str(&format!("<meta name=\"asm-verify\" content=\"{TOKEN}\">"));
        let (port, h) = serve(vec![http("200 OK", "", &page), http("200 OK", "", &big)]).await;
        let t = target(port, "/shop/");
        let o = check(&t, &verify(VerifyMethod::Meta), TIMEOUT).await;
        assert!(o.result.found, "{o:?}");
        // token 在 512 KiB 之後：不算
        let o = check(&t, &verify(VerifyMethod::Meta), TIMEOUT).await;
        assert!(o.responded && !o.result.found);
        let heads = h.await.unwrap();
        assert!(heads[0].starts_with("GET /shop/ HTTP/1.1\r\n"), "{}", heads[0]);
    }

    #[tokio::test]
    async fn unreachable_target_has_no_response() {
        // 先綁再關，拿一個沒人在聽的 port
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let o = check(
            &target(port, "/"),
            &verify(VerifyMethod::WellKnown),
            Duration::from_secs(3),
        )
        .await;
        assert!(!o.responded);
        assert_eq!(o.result.http_status, None);
        assert!(!o.result.found);
        assert!(
            o.result.detail.is_ascii() && !o.result.detail.is_empty(),
            "{}",
            o.result.detail
        );
    }

    #[test]
    fn meta_parsing_is_lenient_but_exact_on_the_token() {
        let yes = [
            format!(r#"<meta name="asm-verify" content="{TOKEN}">"#),
            format!(r#"<meta content="{TOKEN}" name="asm-verify" />"#),
            format!("<META NAME='Asm-Verify' CONTENT='{TOKEN}'>"),
            format!("<meta name=asm-verify content={TOKEN}>"),
            format!("<meta\n  name = \"asm-verify\"\n  content = \" {TOKEN} \"\n>"),
            format!(
                r#"<meta charset="utf-8"><meta name="other" content="x"><meta name="asm-verify" content="{TOKEN}">"#
            ),
        ];
        for html in &yes {
            assert!(meta_has_token(html, TOKEN), "{html}");
        }
        let no = [
            format!(r#"<meta name="asm-verify" content="{TOKEN}x">"#),
            format!(r#"<meta name="asm-verify-x" content="{TOKEN}">"#),
            format!(r#"<meta property="asm-verify" content="{TOKEN}">"#),
            format!(r#"<p>asm-verify {TOKEN}</p>"#),
            r#"<meta name="asm-verify" content="">"#.to_string(),
        ];
        for html in &no {
            assert!(!meta_has_token(html, TOKEN), "{html}");
        }
    }
}
