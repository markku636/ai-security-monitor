//! 掃描範圍檢查（runner 端；Hub 端在 `hub/lib/webscan/scope.ts` 建工作時先檢查過一次，這裡再強制一次）。
//!
//! 執行任何步驟前跑：scheme 只能 http／https；網址解析後的 scheme／host／port／path 要跟目標欄位一致；
//! 目標主機要在範圍內；每個釘選位址：loopback、link-local、multicast、未指定、保留網段（含內嵌 IPv4 的轉譯網段）
//! 一律擋，雲端 metadata 位址無條件擋，這台自己的位址與預設閘道擋，私有位址要落在管理員的內網白名單。任何一項不過就整個工作不做。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use super::job::{RawScope, RawTarget};
use crate::util::net::{classify, IpClass};

/// 一個目標最多幾個釘選位址（跟 Hub 一樣）。
pub const MAX_PINNED_IPS: usize = 16;
pub const MAX_PATH: usize = 512;
pub const MAX_URL: usize = 2048;

/// 雲端 metadata 位址：無條件擋（就算落在內網白名單裡）。
const METADATA_V4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(169, 254, 169, 254), // AWS／GCP／Azure／OpenStack…
    Ipv4Addr::new(169, 254, 170, 2),   // AWS ECS task metadata
    Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud
];
const METADATA_V6: [Ipv6Addr; 1] = [Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)]; // AWS IMDS（IPv6）

/// 不准當目標的名稱：本機、雲端 metadata、compose 裡的內部服務（跟 Hub 的清單一樣）。
const FORBIDDEN_NAMES: [&str; 9] = [
    "localhost",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "instance-data.ec2.internal",
    "hub",
    "postgres",
    "webscan",
    "zap",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// 通過檢查的目標。工具的參數只從這裡組（不用 Hub 給的原始字串）。
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub scheme: Scheme,
    /// 小寫、沒有結尾點；IPv6 不含中括號。
    pub host: String,
    /// 目標本身就是 IP（這時釘選位址只能是它）。
    pub host_ip: Option<IpAddr>,
    pub port: u16,
    pub path: String,
    /// 工具只准連的位址（正規化、去重，照 Hub 給的順序）。
    pub pinned: Vec<IpAddr>,
    /// 範圍內的名稱（釘選 DNS 與 hosts 檔只回答這些）。
    pub names: Vec<String>,
    /// 有落在內網白名單裡的私有位址。
    pub internal: bool,
}

impl Target {
    /// 網址裡的主機（IPv6 加中括號）。
    pub fn host_for_url(&self) -> String {
        match self.host_ip {
            Some(IpAddr::V6(v6)) => format!("[{v6}]"),
            _ => self.host.clone(),
        }
    }

    /// `host:port`（IPv6 加中括號）。
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host_for_url(), self.port)
    }

    /// 換一個路徑的網址（預設 port 省略）。`path` 要以 `/` 開頭。
    pub fn url_with_path(&self, path: &str) -> String {
        let port = if self.port == self.scheme.default_port() {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        format!("{}://{}{port}{path}", self.scheme.as_str(), self.host_for_url())
    }

    /// 由驗證過的欄位重新組出來的目標網址。
    pub fn url(&self) -> String {
        self.url_with_path(&self.path)
    }
}

/// 被擋的原因（代碼跟 Hub 端一致；回報成 `blocked_target:<代碼>`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    BadScheme,
    BadUrl,
    UrlMismatch,
    UrlCredentials,
    BadHost,
    ForbiddenHost,
    HostNotInScope,
    BadScopeHost,
    NoPinnedIps,
    TooManyIps,
    InvalidIp,
    InvalidCidr,
    Metadata,
    Unspecified,
    Loopback,
    LinkLocal,
    Multicast,
    Reserved,
    SelfAddr,
    PrivateNotAllowed,
    IpHostMismatch,
}

impl Blocked {
    pub fn code(self) -> &'static str {
        match self {
            Blocked::BadScheme => "bad_scheme",
            Blocked::BadUrl => "bad_url",
            Blocked::UrlMismatch => "url_mismatch",
            Blocked::UrlCredentials => "url_credentials",
            Blocked::BadHost => "bad_host",
            Blocked::ForbiddenHost => "forbidden_host",
            Blocked::HostNotInScope => "host_not_in_scope",
            Blocked::BadScopeHost => "bad_scope_host",
            Blocked::NoPinnedIps => "no_pinned_ips",
            Blocked::TooManyIps => "too_many_ips",
            Blocked::InvalidIp => "invalid_ip",
            Blocked::InvalidCidr => "invalid_cidr",
            Blocked::Metadata => "metadata",
            Blocked::Unspecified => "unspecified",
            Blocked::Loopback => "loopback",
            Blocked::LinkLocal => "link_local",
            Blocked::Multicast => "multicast",
            Blocked::Reserved => "reserved",
            Blocked::SelfAddr => "self",
            Blocked::PrivateNotAllowed => "private_not_allowed",
            Blocked::IpHostMismatch => "ip_host_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    Name(String),
    Ip(IpAddr),
}

/// 主機名稱：小寫英數、連字號、底線（不在最後一段）；每段 1～63、不以連字號開頭或結尾；總長 ≤ 253；
/// 最後一段要以字母開頭（擋掉 `127.1`、`0x7f.1` 這種會被某些解析器當成 IP 的寫法）。
fn valid_hostname(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    for l in &labels {
        if l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') {
            return false;
        }
        if !l
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
        {
            return false;
        }
    }
    let last = labels.last().copied().unwrap_or_default();
    last.as_bytes().first().is_some_and(|c| c.is_ascii_lowercase()) && !last.contains('_')
}

/// 正規化主機：IP 字面值（可帶中括號）或主機名稱（不分大小寫、可帶一個結尾點）。不接受任何空白。
fn parse_host(raw: &str) -> Option<Host> {
    if raw.is_empty() || raw.len() > 255 {
        return None;
    }
    let bare = raw.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(raw);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Some(Host::Ip(ip.to_canonical()));
    }
    let name = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    valid_hostname(&name).then_some(Host::Name(name))
}

/// 路徑：`/` 開頭、≤ 512；只收 RFC 3986 的 pchar（不含引號、空白、反斜線、`<>{}|^`、控制字元、非 ASCII），`%` 後面要是兩個十六進位數字。
fn valid_path(p: &str) -> bool {
    if !p.starts_with('/') || p.len() > MAX_PATH {
        return false;
    }
    let b = p.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            if !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit) && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)) {
                return false;
            }
            i += 3;
            continue;
        }
        let ok = c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
            );
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

fn forbidden(name: &str) -> bool {
    FORBIDDEN_NAMES.contains(&name)
        || name.ends_with(".localhost")
        || (name.starts_with("metadata.") && name.ends_with(".internal"))
}

fn is_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => METADATA_V4.contains(&v4),
        IpAddr::V6(v6) => METADATA_V6.contains(&v6),
    }
}

/// `util::net::classify` 沒有涵蓋、但不該當目標的網段（跟 Hub 的保留清單一致，再加上 `::/64` 與 site-local）。
fn extra_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 協定指派
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 6to4 relay
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 效能測試
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[..4] == [0, 0, 0, 0] // ::/64：IPv4-compatible／translated（內嵌 IPv4，可能繞到 127.0.0.1）
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // 100::/64 discard
                || (s[0] == 0x2001 && s[1] == 0) // 2001::/32 Teredo（內嵌 IPv4）
                || s[0] == 0x2002 // 2002::/16 6to4（內嵌 IPv4）
                || (s[0] == 0x0064 && s[1] == 0xff9b) // 64:ff9b::/96、64:ff9b:1::/48 NAT64（內嵌 IPv4）
                || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 已廢止的 site-local
        }
    }
}

/// 一個釘選位址能不能掃：`Ok(true)`＝私有位址（在白名單內）、`Ok(false)`＝公網。
pub fn check_ip(ip: IpAddr, allowed: &[IpNet], self_ips: &[IpAddr]) -> Result<bool, Blocked> {
    let ip = ip.to_canonical();
    if is_metadata(ip) {
        return Err(Blocked::Metadata);
    }
    let class = classify(ip);
    match class {
        IpClass::Unspecified => return Err(Blocked::Unspecified),
        IpClass::Loopback => return Err(Blocked::Loopback),
        IpClass::LinkLocal => return Err(Blocked::LinkLocal),
        IpClass::Multicast => return Err(Blocked::Multicast),
        IpClass::Reserved => return Err(Blocked::Reserved),
        IpClass::Private | IpClass::Public => {}
    }
    if extra_reserved(ip) {
        return Err(Blocked::Reserved);
    }
    if self_ips.iter().any(|s| s.to_canonical() == ip) {
        return Err(Blocked::SelfAddr);
    }
    if class == IpClass::Private {
        return if allowed.iter().any(|n| n.contains(&ip)) {
            Ok(true)
        } else {
            Err(Blocked::PrivateNotAllowed)
        };
    }
    Ok(false)
}

fn parse_cidr(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
        .map(|n| n.trunc())
}

/// 網址要跟目標欄位一致（scheme、host、port、path；不能有帳密、query、fragment）。
fn check_url(raw: &str, scheme: Scheme, host: &Host, port: u16, path: &str) -> Result<(), Blocked> {
    if raw.is_empty() || raw.len() > MAX_URL || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Blocked::BadUrl);
    }
    let u = reqwest::Url::parse(raw).map_err(|_| Blocked::BadUrl)?;
    if u.scheme() != scheme.as_str() {
        return Err(Blocked::UrlMismatch);
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(Blocked::UrlCredentials);
    }
    let url_host = u.host_str().and_then(parse_host);
    if url_host.as_ref() != Some(host)
        || u.port_or_known_default() != Some(port)
        || u.path() != path
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(Blocked::UrlMismatch);
    }
    Ok(())
}

/// 檢查一個工作的目標與範圍；`self_ips` 是這台自己所有網卡的位址＋預設閘道（見 `runner::self_ips`）。
pub fn check(t: &RawTarget, s: &RawScope, self_ips: &[IpAddr]) -> Result<Target, Blocked> {
    let scheme = match t.scheme.as_str() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        _ => return Err(Blocked::BadScheme),
    };
    let host = parse_host(&t.host).ok_or(Blocked::BadHost)?;
    if let Host::Name(n) = &host {
        if forbidden(n) {
            return Err(Blocked::ForbiddenHost);
        }
    }
    if t.port == 0 || !valid_path(&t.path) {
        return Err(Blocked::BadUrl);
    }
    check_url(&t.url, scheme, &host, t.port, &t.path)?;

    let mut names: Vec<String> = Vec::new();
    let mut in_scope = false;
    for raw in &s.hosts {
        let h = parse_host(raw).ok_or(Blocked::BadScopeHost)?;
        if let Host::Name(n) = &h {
            if forbidden(n) {
                return Err(Blocked::ForbiddenHost);
            }
            if !names.contains(n) {
                names.push(n.clone());
            }
        }
        in_scope |= h == host;
    }
    if !in_scope {
        return Err(Blocked::HostNotInScope);
    }
    let allowed = s
        .allowed_private_cidrs
        .iter()
        .map(|c| parse_cidr(c).ok_or(Blocked::InvalidCidr))
        .collect::<Result<Vec<_>, _>>()?;

    if t.pinned_ips.is_empty() {
        return Err(Blocked::NoPinnedIps);
    }
    if t.pinned_ips.len() > MAX_PINNED_IPS {
        return Err(Blocked::TooManyIps);
    }
    let mut pinned: Vec<IpAddr> = Vec::new();
    let mut internal = false;
    for raw in &t.pinned_ips {
        let ip = raw.parse::<IpAddr>().map_err(|_| Blocked::InvalidIp)?.to_canonical();
        internal |= check_ip(ip, &allowed, self_ips)?;
        if !pinned.contains(&ip) {
            pinned.push(ip);
        }
    }
    // 目標本身是 IP：工具會直接連它（不經 DNS），所以釘選位址只能是它
    let host_ip = match &host {
        Host::Ip(ip) => {
            if pinned.iter().any(|p| p != ip) {
                return Err(Blocked::IpHostMismatch);
            }
            Some(*ip)
        }
        Host::Name(_) => None,
    };
    let host = match host {
        Host::Name(n) => n,
        Host::Ip(ip) => ip.to_string(),
    };
    Ok(Target {
        scheme,
        host,
        host_ip,
        port: t.port,
        path: t.path.clone(),
        pinned,
        names,
        internal,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn raw_target(url: &str, host: &str, port: u16, path: &str, ips: &[&str]) -> RawTarget {
        RawTarget {
            id: "wt_1".into(),
            url: url.into(),
            scheme: url.split("://").next().unwrap_or_default().into(),
            host: host.into(),
            port,
            path: path.into(),
            pinned_ips: ips.iter().map(|s| s.to_string()).collect(),
            internal: false,
        }
    }

    pub(crate) fn raw_scope(hosts: &[&str], cidrs: &[&str]) -> RawScope {
        RawScope {
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            allowed_private_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn shop(ips: &[&str]) -> RawTarget {
        raw_target("https://shop.example.com/", "shop.example.com", 443, "/", ips)
    }

    fn check_ips(ips: &[&str], cidrs: &[&str], self_ips: &[&str]) -> Result<Target, Blocked> {
        let me: Vec<IpAddr> = self_ips.iter().map(|s| s.parse().unwrap()).collect();
        check(&shop(ips), &raw_scope(&["shop.example.com"], cidrs), &me)
    }

    #[test]
    fn public_target_passes_and_url_is_rebuilt() {
        let t = check_ips(&["8.8.8.8", "2606:4700::1111", "8.8.8.8"], &[], &["172.20.0.5"]).unwrap();
        assert_eq!(t.scheme, Scheme::Https);
        assert_eq!(t.host, "shop.example.com");
        assert_eq!(t.host_ip, None);
        assert_eq!(
            t.pinned,
            vec!["8.8.8.8".parse::<IpAddr>().unwrap(), "2606:4700::1111".parse().unwrap()],
            "deduplicated, order kept"
        );
        assert_eq!(t.names, vec!["shop.example.com".to_string()]);
        assert!(!t.internal);
        assert_eq!(t.url(), "https://shop.example.com/");
        assert_eq!(t.host_port(), "shop.example.com:443");
        assert_eq!(
            t.url_with_path("/.well-known/asm-verify.txt"),
            "https://shop.example.com/.well-known/asm-verify.txt"
        );
    }

    #[test]
    fn private_target_needs_the_allowlist() {
        let t = check_ips(&["10.1.2.3"], &["10.0.0.0/8"], &[]).unwrap();
        assert!(t.internal);
        assert_eq!(check_ips(&["10.1.2.3"], &[], &[]), Err(Blocked::PrivateNotAllowed));
        assert_eq!(
            check_ips(&["10.1.2.3"], &["192.168.0.0/16"], &[]),
            Err(Blocked::PrivateNotAllowed)
        );
        // 單一 IP 也可以當白名單；CGNAT 與 ULA 都算私有
        assert!(check_ips(&["192.168.1.20"], &["192.168.1.20"], &[]).unwrap().internal);
        assert!(check_ips(&["100.64.1.1"], &["100.64.0.0/10"], &[]).is_ok());
        assert!(check_ips(&["fd12::5"], &["fd12::/16"], &[]).is_ok());
        assert_eq!(check_ips(&["fd12::5"], &[], &[]), Err(Blocked::PrivateNotAllowed));
        // 一個公網、一個私有（在白名單內）也行
        assert!(
            check_ips(&["8.8.8.8", "10.0.0.9"], &["10.0.0.0/24"], &[])
                .unwrap()
                .internal
        );
        assert_eq!(
            check_ips(&["10.1.2.3"], &["not-a-cidr"], &[]),
            Err(Blocked::InvalidCidr)
        );
    }

    #[test]
    fn dangerous_addresses_are_blocked_even_when_allowlisted() {
        let all = ["0.0.0.0/0", "::/0"];
        let cases: &[(&str, Blocked)] = &[
            ("127.0.0.1", Blocked::Loopback),
            ("127.8.9.10", Blocked::Loopback),
            ("::1", Blocked::Loopback),
            ("::ffff:127.0.0.1", Blocked::Loopback),
            ("169.254.1.1", Blocked::LinkLocal),
            ("fe80::1", Blocked::LinkLocal),
            ("224.0.0.1", Blocked::Multicast),
            ("ff02::1", Blocked::Multicast),
            ("0.0.0.0", Blocked::Unspecified),
            ("::", Blocked::Unspecified),
            ("240.0.0.1", Blocked::Reserved),
            ("255.255.255.255", Blocked::Reserved),
            ("0.1.2.3", Blocked::Reserved),
            ("203.0.113.10", Blocked::Reserved),
            ("192.0.2.1", Blocked::Reserved),
            ("198.18.0.1", Blocked::Reserved),
            ("192.0.0.8", Blocked::Reserved),
            ("2001:db8::1", Blocked::Reserved),
            ("2002:7f00:1::1", Blocked::Reserved),
            ("64:ff9b::7f00:1", Blocked::Reserved),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", Blocked::Reserved),
            ("::127.0.0.1", Blocked::Reserved),
            ("fec0::1", Blocked::Reserved),
            ("169.254.169.254", Blocked::Metadata),
            ("169.254.170.2", Blocked::Metadata),
            ("100.100.100.200", Blocked::Metadata),
            ("fd00:ec2::254", Blocked::Metadata),
            ("::ffff:169.254.169.254", Blocked::Metadata),
        ];
        for (ip, want) in cases {
            assert_eq!(check_ips(&[ip], &all, &[]), Err(*want), "{ip}");
            // 混在正常位址裡一樣整個擋
            assert_eq!(
                check_ips(&["8.8.8.8", ip], &all, &[]),
                Err(*want),
                "{ip} among good ones"
            );
        }
    }

    #[test]
    fn own_addresses_are_blocked() {
        assert_eq!(
            check_ips(&["10.0.0.5"], &["10.0.0.0/8"], &["10.0.0.5"]),
            Err(Blocked::SelfAddr)
        );
        assert_eq!(check_ips(&["8.8.4.4"], &[], &["8.8.4.4"]), Err(Blocked::SelfAddr));
        assert_eq!(
            check_ips(&["::ffff:10.0.0.5"], &["10.0.0.0/8"], &["10.0.0.5"]),
            Err(Blocked::SelfAddr)
        );
    }

    #[test]
    fn pinned_ip_list_rules() {
        assert_eq!(check_ips(&[], &[], &[]), Err(Blocked::NoPinnedIps));
        for bad in ["not-an-ip", "10.0.0.1%eth0", " 8.8.8.8", "8.8.8.8/32", "[::1]"] {
            assert_eq!(check_ips(&[bad], &[], &[]), Err(Blocked::InvalidIp), "{bad}");
        }
        let many: Vec<String> = (1..=17).map(|i| format!("8.8.8.{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(check_ips(&many, &[], &[]), Err(Blocked::TooManyIps));
    }

    #[test]
    fn url_must_match_the_target_fields() {
        let scope = raw_scope(&["shop.example.com"], &[]);
        let ok = |url: &str, host: &str, port: u16, path: &str| {
            check(&raw_target(url, host, port, path, &["8.8.8.8"]), &scope, &[])
        };
        // 大小寫、結尾點、明寫的預設 port 都算同一個
        let t = ok("https://SHOP.Example.com.:443/", "Shop.Example.COM.", 443, "/").unwrap();
        assert_eq!(t.host, "shop.example.com");
        assert_eq!(t.url(), "https://shop.example.com/");
        let t = ok(
            "http://shop.example.com:8080/app/x%20y",
            "shop.example.com",
            8080,
            "/app/x%20y",
        )
        .unwrap();
        assert_eq!(t.url(), "http://shop.example.com:8080/app/x%20y");
        let cases: &[(&str, &str, u16, &str, Blocked)] = &[
            (
                "ftp://shop.example.com/",
                "shop.example.com",
                21,
                "/",
                Blocked::BadScheme,
            ),
            (
                "http://shop.example.com/",
                "shop.example.com",
                443,
                "/",
                Blocked::UrlMismatch,
            ),
            (
                "https://evil.example.net/",
                "shop.example.com",
                443,
                "/",
                Blocked::UrlMismatch,
            ),
            (
                "https://shop.example.com:8443/",
                "shop.example.com",
                443,
                "/",
                Blocked::UrlMismatch,
            ),
            (
                "https://shop.example.com/admin",
                "shop.example.com",
                443,
                "/",
                Blocked::UrlMismatch,
            ),
            (
                "https://shop.example.com/?q=1",
                "shop.example.com",
                443,
                "/",
                Blocked::UrlMismatch,
            ),
            (
                "https://shop.example.com/#x",
                "shop.example.com",
                443,
                "/",
                Blocked::UrlMismatch,
            ),
            (
                "https://shop.example.com/a/../b",
                "shop.example.com",
                443,
                "/a/../b",
                Blocked::UrlMismatch,
            ),
            (
                "https://user:pw@shop.example.com/",
                "shop.example.com",
                443,
                "/",
                Blocked::UrlCredentials,
            ),
            (
                "https://shop.example.com/ -o /etc/passwd",
                "shop.example.com",
                443,
                "/",
                Blocked::BadUrl,
            ),
            (
                "https://shop.example.com/\"x\"",
                "shop.example.com",
                443,
                "/\"x\"",
                Blocked::BadUrl,
            ),
            (
                "https://shop.example.com/x'y",
                "shop.example.com",
                443,
                "/x'y",
                Blocked::BadUrl,
            ),
            (
                "https://shop.example.com/a\\b",
                "shop.example.com",
                443,
                "/a\\b",
                Blocked::BadUrl,
            ),
            (
                "https://shop.example.com/%zz",
                "shop.example.com",
                443,
                "/%zz",
                Blocked::BadUrl,
            ),
            ("https://not a url", "shop.example.com", 443, "/", Blocked::BadUrl),
            ("https://", "shop.example.com", 443, "/", Blocked::BadUrl),
            ("https://shop.example.com/", "shop.example.com", 0, "/", Blocked::BadUrl),
            (
                "https://shop.example.com/",
                "shop.example.com",
                443,
                "noslash",
                Blocked::BadUrl,
            ),
        ];
        for (url, host, port, path, want) in cases {
            assert_eq!(ok(url, host, *port, path), Err(*want), "{url} / {host}:{port}{path}");
        }
    }

    #[test]
    fn malicious_hosts_are_rejected() {
        let scope = |h: &str| raw_scope(&[h], &[]);
        for bad in [
            "shop.example.com -oX",
            "-oProxy.example.com",
            "\"shop.example.com\"",
            "shop.example.com'",
            "shop example.com",
            " shop.example.com",
            "shop..example.com",
            "shop.example.com..",
            "sh\top.example.com",
            "127.1",
            "0x7f.1",
            "shop.example.c_m",
            "-",
            "",
            "ex%61mple.com",
            "shop.例子.com",
        ] {
            let t = raw_target("https://shop.example.com/", bad, 443, "/", &["8.8.8.8"]);
            assert_eq!(check(&t, &scope(bad), &[]), Err(Blocked::BadHost), "{bad:?}");
        }
        // 範圍裡有壞名稱也整個不做
        let t = shop(&["8.8.8.8"]);
        assert_eq!(
            check(&t, &raw_scope(&["shop.example.com", "x -y"], &[]), &[]),
            Err(Blocked::BadScopeHost)
        );
    }

    #[test]
    fn scope_and_forbidden_names() {
        let t = shop(&["8.8.8.8"]);
        assert_eq!(
            check(&t, &raw_scope(&["www.example.com"], &[]), &[]),
            Err(Blocked::HostNotInScope)
        );
        assert_eq!(check(&t, &raw_scope(&[], &[]), &[]), Err(Blocked::HostNotInScope));
        // 範圍不分大小寫、可帶結尾點；多的名稱也會進釘選 DNS
        let ok = check(&t, &raw_scope(&["SHOP.example.com.", "www.example.com"], &[]), &[]).unwrap();
        assert_eq!(
            ok.names,
            vec!["shop.example.com".to_string(), "www.example.com".to_string()]
        );
        for name in [
            "localhost",
            "api.localhost",
            "metadata.google.internal",
            "metadata.foo.internal",
            "hub",
            "postgres",
        ] {
            let t = raw_target(&format!("https://{name}/"), name, 443, "/", &["8.8.8.8"]);
            assert_eq!(
                check(&t, &raw_scope(&[name], &[]), &[]),
                Err(Blocked::ForbiddenHost),
                "{name}"
            );
        }
    }

    #[test]
    fn ip_literal_targets_must_pin_themselves() {
        let scope = raw_scope(&["8.8.8.8"], &[]);
        let t = raw_target("https://8.8.8.8/", "8.8.8.8", 443, "/", &["8.8.8.8"]);
        let ok = check(&t, &scope, &[]).unwrap();
        assert_eq!(ok.host_ip, Some("8.8.8.8".parse().unwrap()));
        assert!(ok.names.is_empty(), "IP literals never go into the pinned DNS");
        let t = raw_target("https://8.8.8.8/", "8.8.8.8", 443, "/", &["1.1.1.1"]);
        assert_eq!(check(&t, &scope, &[]), Err(Blocked::IpHostMismatch));
        let t = raw_target("https://8.8.8.8/", "8.8.8.8", 443, "/", &["8.8.8.8", "1.1.1.1"]);
        assert_eq!(check(&t, &scope, &[]), Err(Blocked::IpHostMismatch));
        // IPv6：網址要有中括號，host 欄位有沒有都可以
        let scope6 = raw_scope(&["2606:4700::1111"], &[]);
        let t = raw_target(
            "https://[2606:4700::1111]:8443/",
            "[2606:4700::1111]",
            8443,
            "/",
            &["2606:4700::1111"],
        );
        let ok = check(&t, &scope6, &[]).unwrap();
        assert_eq!(ok.url(), "https://[2606:4700::1111]:8443/");
        assert_eq!(ok.host_port(), "[2606:4700::1111]:8443");
        // IP 目標也要過位址檢查
        let t = raw_target("http://127.0.0.1/", "127.0.0.1", 80, "/", &["127.0.0.1"]);
        assert_eq!(check(&t, &raw_scope(&["127.0.0.1"], &[]), &[]), Err(Blocked::Loopback));
    }
}
