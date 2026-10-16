//! Windows 事件 XML（`EventRecord.ToXml()`／wevtutil 輸出）→ `NormEvent`。
//! System 區塊取 Provider、EventID、Level、TimeCreated、Channel、Computer；
//! EventData 的 `<Data Name='x'>` 用名稱、沒名稱的依序叫 `Data0`、`Data1`…；UserData 取葉節點名稱。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;

use super::model::NormEvent;

fn entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let n = name.strip_prefix('#')?;
            let code = match n.strip_prefix('x') {
                Some(h) => u32::from_str_radix(h, 16).ok()?,
                None => n.parse().ok()?,
            };
            char::from_u32(code)
        }
    }
}

fn attr(e: &quick_xml::events::BytesStart, key: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.local_name().as_ref() == key)
        .and_then(|a| {
            a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .ok()
                .map(|v| v.to_string())
        })
}

/// 解析一筆事件；`channel_hint` 用在 XML 沒有 Channel 時（不太會發生）。
pub fn parse_event(xml: &str, channel_hint: &str) -> Option<NormEvent> {
    let mut r = Reader::from_str(xml);
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut ev = NormEvent {
        source: "windows".into(),
        channel: channel_hint.into(),
        provider: String::new(),
        event_id: 0,
        level: 4,
        time: DateTime::<Utc>::MIN_UTC,
        computer: String::new(),
        data: BTreeMap::new(),
        message: None,
    };
    let mut data_name: Option<String> = None;
    let mut unnamed = 0usize;
    let mut saw_event = false;
    loop {
        match r.read_event().ok()? {
            Event::Start(e) => {
                let name = e.local_name().as_ref().to_string();
                if name == "Event" {
                    saw_event = true;
                }
                if name == "Data" {
                    data_name = attr(&e, "Name");
                }
                text.clear();
                path.push(name);
            }
            Event::Empty(e) => {
                let name = e.local_name().as_ref().to_string();
                match name.as_str() {
                    "Provider" => ev.provider = attr(&e, "Name").unwrap_or_default(),
                    "TimeCreated" => {
                        if let Some(t) = attr(&e, "SystemTime").and_then(|s| DateTime::parse_from_rfc3339(&s).ok()) {
                            ev.time = t.with_timezone(&Utc);
                        }
                    }
                    "Data" if path.last().map(|p| p == "EventData").unwrap_or(false) => {
                        let k = attr(&e, "Name").unwrap_or_else(|| {
                            unnamed += 1;
                            format!("Data{}", unnamed - 1)
                        });
                        ev.data.insert(k, String::new());
                    }
                    _ => {}
                }
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::CData(t) => text.push_str(&t),
            Event::GeneralRef(r) => {
                if let Some(c) = entity(&r) {
                    text.push(c);
                }
            }
            Event::End(_) => {
                let name = path.pop().unwrap_or_default();
                let parent = path.last().map(String::as_str).unwrap_or("");
                let value = text.trim().to_string();
                match (parent, name.as_str()) {
                    ("System", "EventID") => ev.event_id = value.parse().unwrap_or(0),
                    ("System", "Level") => ev.level = value.parse().unwrap_or(4),
                    ("System", "Channel") => ev.channel = value,
                    ("System", "Computer") => ev.computer = value,
                    ("EventData", "Data") => {
                        let k = data_name.take().unwrap_or_else(|| {
                            unnamed += 1;
                            format!("Data{}", unnamed - 1)
                        });
                        ev.data.insert(k, crate::util::text::clip(&value, 1024));
                    }
                    ("RenderingInfo", "Message") => {
                        if !value.is_empty() {
                            ev.message = Some(crate::util::text::clip(
                                &value.split_whitespace().collect::<Vec<_>>().join(" "),
                                400,
                            ));
                        }
                    }
                    _ => {
                        // UserData 下的葉節點（例：1102 的 SubjectUserName）
                        if path.iter().any(|p| p == "UserData") && !value.is_empty() {
                            ev.data
                                .entry(name)
                                .or_insert_with(|| crate::util::text::clip(&value, 1024));
                        }
                    }
                }
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    (saw_event && ev.event_id != 0 && ev.time != DateTime::<Utc>::MIN_UTC).then_some(ev)
}

#[cfg(test)]
pub(crate) mod samples {
    //! 測試用事件 XML（格式與 Get-WinEvent .ToXml() 相同）。
    pub fn event(provider: &str, id: u32, level: u8, time: &str, channel: &str, data: &[(&str, &str)]) -> String {
        let d: String = data
            .iter()
            .map(|(k, v)| {
                let v = v.replace('&', "&amp;").replace('<', "&lt;");
                if k.is_empty() {
                    format!("<Data>{v}</Data>")
                } else {
                    format!("<Data Name='{k}'>{v}</Data>")
                }
            })
            .collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{provider}' Guid='{{00000000-0000-0000-0000-000000000000}}'/><EventID Qualifiers='0'>{id}</EventID><Version>0</Version><Level>{level}</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='{time}'/><EventRecordID>1</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>{channel}</Channel><Computer>DESKTOP-TEST</Computer><Security/></System><EventData>{d}</EventData></Event>"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_system_and_named_data() {
        let x = samples::event(
            "Microsoft-Windows-Kernel-Power",
            41,
            1,
            "2026-10-10T03:12:44.1234567Z",
            "System",
            &[
                ("BugcheckCode", "126"),
                ("BugcheckParameter1", "0xffffffffc0000005"),
                ("SleepInProgress", "0"),
            ],
        );
        let e = parse_event(&x, "").unwrap();
        assert_eq!(
            (e.event_id, e.level, e.channel.as_str(), e.computer.as_str()),
            (41, 1, "System", "DESKTOP-TEST")
        );
        assert_eq!(e.provider, "Microsoft-Windows-Kernel-Power");
        assert_eq!(e.get("BugcheckCode"), Some("126"));
        assert_eq!(
            e.time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2026-10-10T03:12:44Z"
        );
    }

    #[test]
    fn unnamed_data_entities_userdata_and_message() {
        let x = samples::event(
            "Application Error",
            1000,
            2,
            "2026-10-10T01:00:00Z",
            "Application",
            &[("", "game.exe"), ("", "1.0"), ("", "x & y")],
        );
        let e = parse_event(&x, "").unwrap();
        assert_eq!(e.get("Data0"), Some("game.exe"));
        assert_eq!(e.get("Data2"), Some("x & y"));

        let user = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><Level>4</Level><TimeCreated SystemTime='2026-10-11T00:00:00.000Z'/><Channel>Security</Channel><Computer>PC</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>mallory</SubjectUserName><SubjectDomainName>PC</SubjectDomainName></LogFileCleared></UserData><RenderingInfo Culture='en-US'><Message>The audit log
   was cleared.</Message></RenderingInfo></Event>";
        let e = parse_event(user, "").unwrap();
        assert_eq!(e.get("SubjectUserName"), Some("mallory"));
        assert_eq!(e.message.as_deref(), Some("The audit log was cleared."));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_event("<nope/>", "").is_none());
        assert!(parse_event("not xml <<<", "").is_none());
    }
}
