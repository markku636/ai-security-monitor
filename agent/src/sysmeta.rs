//! 以 sysinfo 補齊 AgentInfo：OS 名稱／版本／核心、開機時間、介面 IP。

use sysinfo::{Networks, System};

use crate::model::report::AgentInfo;

pub fn enrich(agent: &mut AgentInfo) {
    agent.os.name = System::name();
    agent.os.version = System::os_version();
    agent.os.kernel = System::kernel_version();
    agent.os.build = System::long_os_version();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrich_fills_os_fields() {
        let mut a = AgentInfo::current("x");
        enrich(&mut a);
        assert!(a.os.name.is_some());
        assert!(a.uptime_s.is_some());
    }
}
