//! 以 sysinfo 補齊 AgentInfo：OS 名稱／版本／核心、開機時間、介面 IP；Windows 另補 ProductType／InstallationType／EditionID。

use sysinfo::{Networks, System};

use crate::model::report::{AgentInfo, OsInfo};
use crate::util::winver::WinEdition;

pub fn enrich(agent: &mut AgentInfo) {
    agent.os.name = System::name();
    agent.os.version = System::os_version();
    agent.os.kernel = System::kernel_version();
    agent.os.build = System::long_os_version();
    if cfg!(windows) {
        apply_windows_edition(&mut agent.os, WinEdition::current());
    }
    agent.uptime_s = Some(System::uptime());
    if agent.hostname == "unknown" {
        if let Some(h) = System::host_name() {
            agent.hostname = h;
        }
    }
    let networks = Networks::new_with_refreshed_list();
    let mut ips: Vec<String> = Vec::new();
    for (_name, data) in &networks {
        for n in data.ip_networks() {
            let cls = crate::util::net::classify(n.addr);
            if matches!(
                cls,
                crate::util::net::IpClass::Loopback
                    | crate::util::net::IpClass::LinkLocal
                    | crate::util::net::IpClass::Unspecified
            ) {
                continue;
            }
            let s = n.addr.to_string();
            if !ips.contains(&s) {
                ips.push(s);
            }
        }
    }
    ips.sort();
    agent.ips = ips;
}

/// 補上 Windows 版本細節。sysinfo 的 os_version 只看組建編號（Server 2022 會變成「10 (20348)」、Server 2025 變成
/// 「11 (26100)」），伺服器改用 ProductName：`Server 2022 Datacenter (Server Core, 20348)`，Hub 顯示成
/// 「Windows Server 2022 Datacenter (Server Core, 20348)」。
pub fn apply_windows_edition(os: &mut OsInfo, e: &WinEdition) {
    os.product_type = e.product_type.clone();
    os.installation_type = e.installation_type.clone();
    os.edition = e.edition_id.clone();
    if !e.is_server() {
        return;
    }
    if let Some(pn) = &e.product_name {
        os.build = Some(pn.clone());
        let short = pn.strip_prefix("Windows ").unwrap_or(pn);
        let mut extra: Vec<String> = Vec::new();
        if e.is_core() {
            extra.push(e.installation_type.clone().unwrap_or_default());
        }
        if let Some(b) = e.build.map(|b| b.to_string()).or_else(|| os.kernel.clone()) {
            extra.push(b);
        }
        os.version = Some(if extra.is_empty() {
            short.to_string()
        } else {
            format!("{short} ({})", extra.join(", "))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_version_uses_product_name() {
        let mut os = OsInfo {
            family: "windows".into(),
            name: Some("Windows".into()),
            version: Some("10 (20348)".into()),
            kernel: Some("20348".into()),
            ..Default::default()
        };
        let core = WinEdition::from_values(
            Some("ServerNT"),
            Some("Server Core"),
            Some("ServerDatacenter"),
            Some("Windows Server 2022 Datacenter"),
            Some("20348"),
        );
        apply_windows_edition(&mut os, &core);
        assert_eq!(
            os.version.as_deref(),
            Some("Server 2022 Datacenter (Server Core, 20348)")
        );
        assert_eq!(os.product_type.as_deref(), Some("server"));
        assert_eq!(os.installation_type.as_deref(), Some("Server Core"));

        let mut client = OsInfo {
            version: Some("11 (26200)".into()),
            ..Default::default()
        };
        let pro = WinEdition::from_values(
            Some("WinNT"),
            Some("Client"),
            Some("Professional"),
            Some("Windows 11 Pro"),
            Some("26200"),
        );
        apply_windows_edition(&mut client, &pro);
        assert_eq!(client.version.as_deref(), Some("11 (26200)"));
        assert_eq!(client.product_type.as_deref(), Some("workstation"));
    }

    #[test]
    fn enrich_fills_os_fields() {
        let mut a = AgentInfo::current("x");
        enrich(&mut a);
        assert!(a.os.name.is_some());
        assert!(a.uptime_s.is_some());
    }
}
