//! 地理 / ASN：DB-IP Lite（CC BY 4.0，需標註「IP Geolocation by DB-IP」）mmdb。

use std::net::IpAddr;
use std::path::Path;

use maxminddb::Reader;
use serde::Deserialize;

use super::fetch::{feed_dir, MMDB_FILE};
use crate::model::connection::GeoInfo;

pub const ATTRIBUTION: &str = "IP Geolocation by DB-IP (https://db-ip.com)";
pub const COUNTRY_FEED: &str = "dbip-country-lite";
pub const ASN_FEED: &str = "dbip-asn-lite";

#[derive(Deserialize)]
struct CountryRec {
    country: Option<IsoRec>,
}

#[derive(Deserialize)]
struct IsoRec {
    iso_code: Option<String>,
}

#[derive(Deserialize)]
struct AsnRec {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

#[derive(Default)]
pub struct GeoDb {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl GeoDb {
    pub fn load(config_dir: &Path) -> GeoDb {
        let open = |id: &str| Reader::open_readfile(feed_dir(config_dir, id).join(MMDB_FILE)).ok();
        GeoDb {
            country: open(COUNTRY_FEED),
            asn: open(ASN_FEED),
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.country.is_some() || self.asn.is_some()
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        let country = self
            .country
            .as_ref()
            .and_then(|r| r.lookup(ip).ok())
            .and_then(|res| res.decode::<CountryRec>().ok().flatten())
            .and_then(|c| c.country)
            .and_then(|c| c.iso_code);
        let asn = self
            .asn
            .as_ref()
            .and_then(|r| r.lookup(ip).ok())
            .and_then(|res| res.decode::<AsnRec>().ok().flatten());
        if country.is_none() && asn.is_none() {
            return None;
        }
        Some(GeoInfo {
            country,
            asn: asn.as_ref().and_then(|a| a.autonomous_system_number),
            org: asn.and_then(|a| a.autonomous_system_organization),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_databases_are_harmless() {
        let dir = tempfile::tempdir().unwrap();
        let g = GeoDb::load(dir.path());
        assert!(!g.is_loaded());
        assert!(g.lookup("8.8.8.8".parse().unwrap()).is_none());
    }
}
