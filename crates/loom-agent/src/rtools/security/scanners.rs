//! Bounded scanner adapters. These parse assets, never execute scanners or accept scanner severity
//! as proof. Unknown records/required fields fail loudly; optional scanner metadata is ignored.

use loom_core::security_state::{AssetInput, AssetKind};
use quick_xml::events::Event;
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_ASSETS: usize = 500;

pub(super) fn parse(format: &str, bytes: &[u8], evidence: &[String]) -> Result<Vec<AssetInput>, String> {
    let input = std::str::from_utf8(bytes).map_err(|_| {
        "Scanner output must be UTF-8; convert or split the source output before importing it.".to_string()
    })?;
    let mut assets = BTreeMap::new();
    if format == "nmap" {
        nmap(input, evidence, &mut assets)?;
    } else if format == "nuclei" {
        for line in input.lines().filter(|l| !l.trim().is_empty()) {
            let row: Value = serde_json::from_str(line)
                .map_err(|e| format!("Malformed nuclei JSONL: {e}. Nothing was imported."))?;
            let locator =
                row.get("matched-at").or_else(|| row.get("host")).and_then(Value::as_str).ok_or_else(|| {
                    "Each nuclei record needs matched-at or host; use nuclei JSONL output.".to_string()
                })?;
            add_locator(locator, evidence, &mut assets)?;
        }
    } else {
        let data: Value =
            serde_json::from_str(input).map_err(|e| format!("Malformed scanner JSON: {e}. Nothing was imported."))?;
        match format {
            "ffuf" => {
                let rows = data
                    .get("results")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "Use ffuf JSON with a results array.".to_string())?;
                for row in rows {
                    let locator = row
                        .get("url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "Each ffuf result needs its absolute url.".to_string())?;
                    add_locator(locator, evidence, &mut assets)?;
                }
            }
            "netexec" => {
                let rows = data.as_array().or_else(|| data.get("hosts").or_else(|| data.get("results")).and_then(Value::as_array))
                    .ok_or_else(|| "Supported netexec JSON is an array, or a hosts/results array of objects with host, hostname, or ip.".to_string())?;
                for row in rows {
                    let host = row
                        .get("host")
                        .or_else(|| row.get("hostname"))
                        .or_else(|| row.get("ip"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| "Each netexec JSON object needs host, hostname, or ip.".to_string())?;
                    let parent = add(AssetKind::Host, host, None, evidence, &mut assets)?;
                    if let Some(port) = row.get("port") {
                        let port = port.as_u64().ok_or_else(|| "A scanner port must be a JSON integer.".to_string())?;
                        let port = u16::try_from(port)
                            .ok()
                            .filter(|p| *p > 0)
                            .ok_or_else(|| "A scanner port must be between one and 65535.".to_string())?;
                        let protocol = match row.get("protocol") {
                            None => "tcp",
                            Some(p) => p.as_str().ok_or_else(|| "A scanner protocol must be a string.".to_string())?,
                        };
                        if !["tcp", "udp", "smb", "ldap", "winrm", "ssh", "http", "https"].contains(&protocol) {
                            return Err(
                                "Unsupported netexec protocol; normalize it to a documented service scheme.".into()
                            );
                        }
                        add(
                            AssetKind::Service,
                            &format!("{protocol}://{}:{port}", authority(host)),
                            Some(parent),
                            evidence,
                            &mut assets,
                        )?;
                    }
                }
            }
            "bloodhound" => {
                let rows = data
                    .get("data")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "Use BloodHound JSON with a data array and meta.type.".to_string())?;
                let kind = match data.pointer("/meta/type").and_then(Value::as_str) {
                    Some("computers" | "domains") => AssetKind::Host,
                    Some("users" | "groups" | "ous" | "containers" | "gpos") => AssetKind::Identity,
                    _ => return Err("Unsupported BloodHound meta.type; import computers, domains, users, groups, ous, containers, or gpos.".into()),
                };
                for row in rows {
                    let locator = row
                        .pointer("/Properties/name")
                        .or_else(|| row.get("ObjectIdentifier"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            "Each BloodHound object needs Properties.name or ObjectIdentifier.".to_string()
                        })?;
                    let record_kind =
                        if row.pointer("/Properties/name").is_some() { kind } else { AssetKind::Identity };
                    add(record_kind, locator, None, evidence, &mut assets)?;
                }
            }
            _ => {
                return Err(
                    "Choose nmap, nuclei, ffuf, netexec, or bloodhound; unsupported scanner formats are not guessed."
                        .into(),
                )
            }
        }
    }
    if assets.is_empty() {
        return Err("The scanner output contains no supported asset observations; nothing was imported.".into());
    }
    // Atomic batch validation checks references at their point of use. Scanner service parents are
    // hosts, so import all hosts before their services rather than sorting only by content hash.
    let mut ordered: Vec<_> = assets.into_iter().collect();
    ordered.sort_by_key(|(id, asset)| (asset.parent.is_some(), id.clone()));
    Ok(ordered.into_iter().map(|(_, asset)| asset).collect())
}

fn authority(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.into()
    }
}

fn add_locator(locator: &str, evidence: &[String], assets: &mut BTreeMap<String, AssetInput>) -> Result<(), String> {
    let kind = if locator.contains("://") { AssetKind::Endpoint } else { AssetKind::Host };
    add(kind, locator, None, evidence, assets)?;
    Ok(())
}

fn add(
    kind: AssetKind,
    locator: &str,
    parent: Option<String>,
    evidence: &[String],
    assets: &mut BTreeMap<String, AssetInput>,
) -> Result<String, String> {
    let input = AssetInput { kind, locator: locator.into(), evidence: evidence.to_vec(), mandatory: true, parent };
    let id = input.id()?;
    if !assets.contains_key(&id) && assets.len() >= MAX_ASSETS {
        return Err(
            "Scanner imports are limited to 500 canonical assets; split the source output before importing it.".into(),
        );
    }
    assets.entry(id.clone()).or_insert(input);
    Ok(id)
}

fn nmap(input: &str, evidence: &[String], assets: &mut BTreeMap<String, AssetInput>) -> Result<(), String> {
    let mut reader = quick_xml::Reader::from_str(input);
    let mut root = false;
    let mut host: Option<(String, String)> = None;
    let mut port: Option<(String, u16, bool)> = None;
    let mut depth = 0usize;
    loop {
        match reader.read_event().map_err(|e| format!("Malformed nmap XML: {e}. Nothing was imported."))? {
            Event::DocType(d) if &*d != b"nmaprun" => {
                return Err(
                    "External or entity-bearing XML DTDs are not accepted; use a plain nmaprun declaration.".into()
                )
            }
            Event::Start(e) | Event::Empty(e) => {
                let name = e.name();
                let mut attrs = BTreeMap::new();
                for attr in e.attributes() {
                    let attr = attr.map_err(|_| "Malformed nmap XML attributes; nothing was imported.".to_string())?;
                    let key = std::str::from_utf8(attr.key.as_ref())
                        .map_err(|_| "XML attribute names must be UTF-8.".to_string())?
                        .to_string();
                    let value = attr
                        .decode_and_unescape_value(reader.decoder())
                        .map_err(|_| "Malformed XML attribute value.".to_string())?
                        .into_owned();
                    attrs.insert(key, value);
                }
                match name.as_ref() {
                    b"nmaprun" if !root && depth == 0 => root = true,
                    b"nmaprun" => {
                        return Err("Use one nmaprun document root, without wrapping or repeated roots.".into())
                    }
                    b"host" => {
                        host = None;
                        port = None;
                    }
                    b"address"
                        if root
                            && matches!(attrs.get("addrtype").map(String::as_str), Some("ipv4" | "ipv6"))
                            && host.is_none() =>
                    {
                        let value = attrs.get("addr").ok_or_else(|| "An nmap address needs addr.".to_string())?;
                        value
                            .parse::<std::net::IpAddr>()
                            .map_err(|_| "An nmap ipv4/ipv6 address is malformed.".to_string())?;
                        let id = add(AssetKind::Host, value, None, evidence, assets)?;
                        host = Some((value.clone(), id));
                    }
                    b"port" if root => {
                        let protocol =
                            attrs.get("protocol").cloned().ok_or_else(|| "An nmap port needs protocol.".to_string())?;
                        if !["tcp", "udp", "sctp"].contains(&protocol.as_str()) {
                            return Err("Unsupported nmap port protocol.".into());
                        }
                        let number = attrs
                            .get("portid")
                            .and_then(|p| p.parse::<u16>().ok())
                            .filter(|p| *p > 0)
                            .ok_or_else(|| "An nmap portid must be between one and 65535.".to_string())?;
                        port = Some((protocol, number, false));
                    }
                    b"state" => {
                        if let Some((_, _, open)) = &mut port {
                            *open = attrs.get("state").is_some_and(|s| s == "open");
                        }
                    }
                    _ => {}
                }
                // Count elements even in ignored scanner metadata so parsing stays bounded.
                depth = depth.saturating_add(1);
                if depth > 100_000 {
                    return Err("The nmap XML contains too many elements; split the output before importing it.".into());
                }
            }
            Event::End(e) => match e.name().as_ref() {
                b"port" => {
                    if let (Some((address, parent)), Some((protocol, number, true))) = (&host, port.take()) {
                        add(
                            AssetKind::Service,
                            &format!("{protocol}://{}:{number}", authority(address)),
                            Some(parent.clone()),
                            evidence,
                            assets,
                        )?;
                    }
                }
                b"host" => {
                    host = None;
                    port = None;
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    if !root {
        return Err("Use nmap XML rooted at nmaprun; arbitrary XML is not a scanner import.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_tracks_host_parent_open_ports_and_ipv6_without_external_entities() {
        let xml = br#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><address addr="::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="443"><state state="open"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>"#;
        let assets = parse("nmap", xml, &["e1".into()]).unwrap();
        assert_eq!(assets.len(), 2);
        let host = assets.iter().find(|a| a.kind == AssetKind::Host).unwrap();
        let service = assets.iter().find(|a| a.kind == AssetKind::Service).unwrap();
        assert_eq!(service.locator, "tcp://[::1]:443");
        assert_eq!(service.parent.as_ref(), Some(&host.id().unwrap()));
        assert!(parse(
            "nmap",
            br#"<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun/>"#,
            &["e1".into()]
        )
        .is_err());
        assert!(parse("nmap", b"<nmaprun><host></nmaprun>", &["e1".into()]).is_err());
    }

    #[test]
    fn json_scanners_extract_assets_without_promoting_findings_or_credentials() {
        for (format, data, count) in [
            (
                "nuclei",
                r#"{"matched-at":"https://example.test/Login","severity":"critical"}
{"host":"https://example.test/Login"}"#,
                1,
            ),
            ("ffuf", r#"{"results":[{"url":"https://example.test/Admin","status":200}]}"#, 1),
            ("netexec", r#"{"hosts":[{"host":"127.0.0.1","port":445,"protocol":"smb","password":"DONTIMPORT"}]}"#, 2),
            (
                "bloodhound",
                r#"{"meta":{"type":"users"},"data":[{"Properties":{"name":"DUMMY@LAB.TEST"},"ObjectIdentifier":"S-1-test"}]}"#,
                1,
            ),
        ] {
            let assets = parse(format, data.as_bytes(), &["e1".into()]).unwrap();
            assert_eq!(assets.len(), count, "{format}");
            let json = serde_json::to_string(&assets).unwrap();
            assert!(!json.contains("DONTIMPORT"));
            assert!(assets.iter().all(|a| a.mandatory));
        }
    }

    #[test]
    fn malformed_late_records_and_resource_limits_fail_without_partial_results() {
        let malformed = b"{\"matched-at\":\"https://example.test/\"}\nnot json\n";
        assert!(parse("nuclei", malformed, &["e1".into()]).is_err());
        let data = (0..501).map(|i| format!(r#"{{"host":"host{i}.test"}}"#)).collect::<Vec<_>>().join("\n");
        assert!(parse("nuclei", data.as_bytes(), &["e1".into()]).is_err());
        assert!(parse("netexec", b"{\"hosts\":[{\"host\":\"a.test\",\"port\":70000}]}", &["e1".into()]).is_err());
        assert!(parse("bloodhound", b"{\"data\":[]}", &["e1".into()]).is_err());
    }
}
