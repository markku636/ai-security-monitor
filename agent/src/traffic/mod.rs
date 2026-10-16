//! 流量分析（類 Wireshark，但只給重點）：
//! - 離線：讀 .pcap／.pcapng（Wireshark、tcpdump、`pktmon` 轉檔都可），逐封包組成流、解 DNS／TLS SNI／HTTP Host；
//! - 即時 flow-lite：不抓封包、免權限，反覆讀 socket 表＋介面計數器。
//!
//! 兩者都產生同一種 `TrafficSummary`（含明文協定、異常 port、大量上傳、週期性連線、可疑 DNS、情資命中），
//! 也是之後交給 AI 解讀與上傳 hub 的格式。

pub mod flow;
pub mod lite;
pub mod offline;
pub mod proto;
pub mod summary;

pub use summary::TrafficSummary;
