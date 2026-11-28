//! Bounded scanner adapters. These parse assets, never execute scanners or accept scanner severity
//! as proof. Quarantined (logout, unsubscribe, single-use token) and queryless static-asset URLs are
//! imported with `mandatory = false` and ordered after mandatory application/API endpoints. Unknown
//! records/required fields fail loudly; optional scanner metadata is ignored.

use ferret_core::security_state::{AssetInput, AssetKind};
use quick_xml::events::Event;
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_ASSETS: usize = 500;
const SAMPLE_ENDPOINTS_LIMIT: usize = 20;

pub(super) struct IngestParsed {
    pub assets: Vec<AssetInput>,
    pub total_discovered: usize,
    pub truncated: bool,
    pub sample_endpoints: Vec<String>,
}

#[cfg(test)]
pub(super) fn parse(format: &str, bytes: &[u8], evidence: &[String]) -> Result<Vec<AssetInput>, String> {
    parse_with_options(format, bytes, evidence, None, None).map(|r| r.assets)
}

pub(super) fn parse_with_options(
    format: &str,
    bytes: &[u8],
    evidence: &[String],
    source_url: Option<&str>,
    fallback_origin: Option<&str>,
) -> Result<IngestParsed, String> {
    let input = std::str::from_utf8(bytes).map_err(|_| {
        "Scanner output must be UTF-8; convert or split the source output before importing it.".to_string()
    })?;
    if matches!(format, "openapi" | "graphql" | "sourcemap") {
        return parse_surface_artifact(format, input, evidence, source_url, fallback_origin);
    }
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
                    "Choose nmap, nuclei, ffuf, netexec, bloodhound, openapi, graphql, or sourcemap; unsupported formats are not guessed."
                        .into(),
                )
            }
        }
    }
    if assets.is_empty() {
        return Err("The scanner output contains no supported asset observations; nothing was imported.".into());
    }
    // Atomic batch validation checks references at their point of use. Scanner service parents are
    // hosts, so import all hosts before their services, and order high-priority mandatory endpoints
    // ahead of generic and non-mandatory static/quarantined endpoints.
    let mut ordered: Vec<_> = assets.into_iter().collect();
    ordered.sort_by_key(|(id, asset)| (asset.parent.is_some(), priority_rank(asset), id.clone()));
    let assets: Vec<AssetInput> = ordered.into_iter().map(|(_, asset)| asset).collect();
    let sample_endpoints = assets
        .iter()
        .filter(|a| a.kind == AssetKind::Endpoint)
        .take(SAMPLE_ENDPOINTS_LIMIT)
        .map(|a| a.locator.clone())
        .collect();
    let total_discovered = assets.len();
    Ok(IngestParsed { assets, total_discovered, truncated: false, sample_endpoints })
}

fn parse_origin(raw: &str) -> Option<(String, String, String)> {
    let u = url::Url::parse(raw.trim()).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    let host = u.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let host_port = match u.port() {
        Some(p) if host.contains(':') => format!("[{host}]:{p}"),
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    let path = u.path().trim_end_matches('/').to_string();
    Some((u.scheme().to_string(), host_port, path))
}

fn parse_surface_artifact(
    format: &str,
    input: &str,
    evidence: &[String],
    source_url: Option<&str>,
    fallback_origin: Option<&str>,
) -> Result<IngestParsed, String> {
    let surfaces = match format {
        "openapi" => ferret_core::ingest::parse_openapi(input)?,
        "graphql" => ferret_core::ingest::parse_graphql_introspection(input)?,
        "sourcemap" => ferret_core::ingest::parse_js_sourcemap(input, source_url.or(fallback_origin))?,
        _ => unreachable!(),
    };
    if surfaces.is_empty() {
        return Err(format!("The {format} artifact contains no discoverable surfaces; nothing was imported."));
    }
    let origin = source_url.and_then(parse_origin).or_else(|| fallback_origin.and_then(parse_origin));
    let total_discovered = surfaces.len();
    let mut assets: BTreeMap<String, AssetInput> = BTreeMap::new();
    let mut sample_endpoints: Vec<String> = Vec::new();
    let mut truncated = false;

    for surface in &surfaces {
        let (kind, locator, mandatory) = match format {
            "sourcemap" if surface.method.eq_ignore_ascii_case("SOURCE") => {
                (AssetKind::File, surface.path.clone(), false)
            }
            "graphql" => {
                let op_slug = format!("{}:{}", surface.method.to_ascii_lowercase(), surface.path);
                if let Some((scheme, host_port, base_path)) = &origin {
                    let gql_path = if base_path.is_empty() { "/graphql" } else { base_path.as_str() };
                    (AssetKind::Endpoint, format!("{scheme}://{host_port}{gql_path}#{op_slug}"), true)
                } else {
                    (AssetKind::File, format!("graphql {op_slug}"), true)
                }
            }
            _ => {
                if surface.path.starts_with("http://") || surface.path.starts_with("https://") {
                    let mand = ferret_tools::http::quarantined_locator(&surface.path).is_none()
                        && !is_non_sourcemap_static_asset(&surface.path);
                    (AssetKind::Endpoint, surface.path.clone(), mand)
                } else if let Some(host) = surface.host.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
                    let scheme = origin.as_ref().map_or("https", |(s, _, _)| s.as_str());
                    let path =
                        if surface.path.starts_with('/') { surface.path.clone() } else { format!("/{}", surface.path) };
                    let url = format!("{scheme}://{host}{path}");
                    let mand =
                        ferret_tools::http::quarantined_locator(&url).is_none() && !is_non_sourcemap_static_asset(&url);
                    (AssetKind::Endpoint, url, mand)
                } else if let Some((scheme, host_port, _)) = &origin {
                    let path =
                        if surface.path.starts_with('/') { surface.path.clone() } else { format!("/{}", surface.path) };
                    let url = format!("{scheme}://{host_port}{path}");
                    let mand =
                        ferret_tools::http::quarantined_locator(&url).is_none() && !is_non_sourcemap_static_asset(&url);
                    (AssetKind::Endpoint, url, mand)
                } else {
                    (AssetKind::File, format!("{} {}", surface.method, surface.path), true)
                }
            }
        };

        let sample_label =
            if kind == AssetKind::Endpoint { format!("{} {}", surface.method, locator) } else { locator.clone() };
        if sample_endpoints.len() < SAMPLE_ENDPOINTS_LIMIT && !sample_endpoints.contains(&sample_label) {
            sample_endpoints.push(sample_label);
        }

        let input_asset = AssetInput { kind, locator, evidence: evidence.to_vec(), mandatory, parent: None };
        let Ok(id) = input_asset.id() else { continue };
        if assets.contains_key(&id) {
            continue;
        }
        if assets.len() >= MAX_ASSETS {
            truncated = true;
            continue;
        }
        assets.insert(id, input_asset);
    }

    if assets.is_empty() {
        return Err(format!(
            "The {format} artifact yielded no canonical asset locators; pass `source_url` (for example https://app.example.test) to resolve relative endpoints."
        ));
    }

    let mut ordered: Vec<_> = assets.into_iter().collect();
    ordered.sort_by_key(|(id, asset)| (asset.parent.is_some(), priority_rank(asset), id.clone()));
    Ok(IngestParsed {
        assets: ordered.into_iter().map(|(_, asset)| asset).collect(),
        total_discovered,
        truncated,
        sample_endpoints,
    })
}

/// Static asset check that intentionally keeps `.map` JS source maps indexed as high-value assets.
fn is_non_sourcemap_static_asset(locator: &str) -> bool {
    if let Ok(u) = url::Url::parse(locator) {
        if u.path().to_ascii_lowercase().ends_with(".map") {
            return false;
        }
    }
    ferret_tools::http::is_static_asset_locator(locator)
}

fn priority_rank(asset: &AssetInput) -> u8 {
    match asset.kind {
        AssetKind::Host | AssetKind::Identity | AssetKind::File => 0,
        AssetKind::Service => 1,
        AssetKind::Endpoint if !asset.mandatory => 4,
        AssetKind::Endpoint => {
            let low = asset.locator.to_ascii_lowercase();
            if low.contains('?')
                || ["/api/", "/admin", "/auth", "/login", "/graphql", "/v1/", "/v2/", "/internal"]
                    .iter()
                    .any(|p| low.contains(p))
            {
                2
            } else {
                3
            }
        }
    }
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
    let mandatory = kind != AssetKind::Endpoint
        || (ferret_tools::http::quarantined_locator(locator).is_none() && !is_non_sourcemap_static_asset(locator));
    let input = AssetInput { kind, locator: locator.into(), evidence: evidence.to_vec(), mandatory, parent };
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
            Event::DocType(d) if &*d != "nmaprun" => {
                return Err(
                    "External or entity-bearing XML DTDs are not accepted; use a plain nmaprun declaration.".into()
                )
            }
            Event::Start(e) | Event::Empty(e) => {
                let name = e.name();
                let mut attrs = BTreeMap::new();
                for attr in e.attributes() {
                    let attr = attr.map_err(|_| "Malformed nmap XML attributes; nothing was imported.".to_string())?;
                    let key = attr.key.as_ref().to_string();
                    let value = attr
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|_| "Malformed XML attribute value.".to_string())?
                        .into_owned();
                    attrs.insert(key, value);
                }
                match name.as_ref() {
                    "nmaprun" if !root && depth == 0 => root = true,
                    "nmaprun" => {
                        return Err("Use one nmaprun document root, without wrapping or repeated roots.".into())
                    }
                    "host" => {
                        host = None;
                        port = None;
                    }
                    "address"
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
                    "port" if root => {
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
                    "state" => {
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
                "port" => {
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
                "host" => {
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

    #[test]
    fn quarantined_and_static_endpoints_are_non_mandatory_and_ordered_after_api_routes() {
        let ffuf = br#"{"results":[
            {"url":"https://example.test/static/app.woff2","status":200},
            {"url":"https://example.test/auth/logout","status":302},
            {"url":"https://example.test/account?reset_token=abc","status":200},
            {"url":"https://example.test/about","status":200},
            {"url":"https://example.test/api/v1/users","status":200}
        ]}"#;
        let assets = parse("ffuf", ffuf, &["e1".into()]).unwrap();
        assert_eq!(assets.len(), 5);
        assert_eq!(assets[0].locator, "https://example.test/api/v1/users");
        assert!(assets[0].mandatory);
        assert_eq!(assets[1].locator, "https://example.test/about");
        assert!(assets[1].mandatory);
        for non_mandatory in &assets[2..] {
            assert!(!non_mandatory.mandatory, "{}", non_mandatory.locator);
        }
    }
}
