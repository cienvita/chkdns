use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::op::ResponseCode;
use hickory_client::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;
use tokio::time::timeout;

const ROOT_SERVERS: &[(&str, [u8; 4])] = &[
    ("a", [198, 41, 0, 4]),
    ("b", [170, 247, 170, 2]),
    ("c", [192, 33, 4, 12]),
    ("d", [199, 7, 91, 13]),
    ("e", [192, 203, 230, 10]),
    ("f", [192, 5, 5, 241]),
    ("g", [192, 112, 36, 4]),
    ("h", [198, 97, 190, 53]),
    ("i", [192, 36, 148, 17]),
    ("j", [192, 58, 128, 30]),
    ("k", [193, 0, 14, 129]),
    ("l", [199, 7, 83, 42]),
    ("m", [202, 12, 27, 33]),
];

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HOPS: usize = 16;
const MAX_DEPTH: u32 = 8;

struct Rng(u64);
impl Rng {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = (self.next() as usize) % (i + 1);
            slice.swap(i, j);
        }
    }
}

fn parse_record_type(s: &str) -> Option<RecordType> {
    let up = s.to_ascii_uppercase();
    match up.as_str() {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "NS" => Some(RecordType::NS),
        "MX" => Some(RecordType::MX),
        "TXT" => Some(RecordType::TXT),
        "CNAME" => Some(RecordType::CNAME),
        "SOA" => Some(RecordType::SOA),
        "PTR" => Some(RecordType::PTR),
        "SRV" => Some(RecordType::SRV),
        "CAA" => Some(RecordType::CAA),
        "ANY" => Some(RecordType::ANY),
        _ => RecordType::from_str(&up).ok(),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 || args[1] == "-h" || args[1] == "--help" {
        eprintln!("usage: chkdns <domain> [type]");
        eprintln!("  type defaults to A. examples: A, AAAA, NS, MX, TXT, SOA, CAA");
        eprintln!("  ANY is accepted but most servers refuse it (RFC 8482)");
        process::exit(2);
    }
    let domain = &args[1];
    let qtype = if args.len() == 3 {
        match parse_record_type(&args[2]) {
            Some(t) => t,
            None => {
                eprintln!("unknown record type '{}'", args[2]);
                process::exit(2);
            }
        }
    } else {
        RecordType::A
    };
    let name = match Name::from_str(domain) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("invalid domain '{domain}': {e}");
            process::exit(2);
        }
    };

    let mut rng = Rng::new();

    println!("== phase 1: walk delegation chain (NS {name}) ==");
    println!();
    let chain = match chain_walk(name.clone(), RecordType::NS, &mut rng, 0).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chain failed: {e}");
            process::exit(1);
        }
    };
    print_query_trace(&chain.steps);
    println!();
    print_steps(&chain.steps, 0);

    let parent_ns_set: HashSet<&Name> = chain.parent_ns.iter().collect();
    let apex_ns: Vec<Name> = chain
        .apex_answer
        .iter()
        .filter_map(|r| match r.data() {
            RData::NS(ns) => Some(ns.0.clone()),
            _ => None,
        })
        .collect();
    let apex_ns_set: HashSet<&Name> = apex_ns.iter().collect();

    if parent_ns_set != apex_ns_set {
        println!("note: parent delegation NS set differs from apex NS RRset");
        println!("  parent ({}):", chain.parent_label);
        let mut parent_sorted: Vec<&Name> = parent_ns_set.iter().copied().collect();
        parent_sorted.sort();
        for n in parent_sorted {
            println!("    {n}");
        }
        println!("  apex (from {}):", chain.auth_label);
        let mut apex_sorted: Vec<&Name> = apex_ns_set.iter().copied().collect();
        apex_sorted.sort();
        for n in apex_sorted {
            println!("    {n}");
        }
        println!();
    }

    println!("== phase 2: query each authoritative server ({qtype} {name}) ==");
    println!();
    poll_auths(&name, qtype, &chain, &apex_ns, &mut rng).await;
}

struct Step {
    server_label: String,
    server_addr: SocketAddr,
    qname: Name,
    qtype: RecordType,
    rcode: ResponseCode,
    aa: bool,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
    skipped: Vec<(String, SocketAddr, String)>,
    sub: Vec<(Name, Vec<Step>)>,
}

struct ChainResult {
    steps: Vec<Step>,
    parent_ns: Vec<Name>,
    parent_glue: Vec<Record>,
    apex_answer: Vec<Record>,
    auth_label: String,
    parent_label: String,
}

struct DnsResp {
    rcode: ResponseCode,
    aa: bool,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
}

async fn query(
    addr: SocketAddr,
    name: Name,
    qtype: RecordType,
) -> Result<DnsResp, Box<dyn std::error::Error + Send + Sync>> {
    let connect = UdpClientStream::builder(addr, TokioRuntimeProvider::new()).build();
    let (mut client, bg) = Client::connect(connect).await?;
    let bg_handle = tokio::spawn(bg);
    let resp = client.query(name, DNSClass::IN, qtype).await?;
    bg_handle.abort();
    Ok(DnsResp {
        rcode: resp.response_code(),
        aa: resp.authoritative(),
        answers: resp.answers().to_vec(),
        authority: resp.name_servers().to_vec(),
        additional: resp.additionals().to_vec(),
    })
}

fn extract_ns_names(records: &[Record]) -> Vec<Name> {
    records
        .iter()
        .filter_map(|r| match r.data() {
            RData::NS(ns) => Some(ns.0.clone()),
            _ => None,
        })
        .collect()
}

fn record_ip(r: &Record) -> Option<IpAddr> {
    match r.data() {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

fn build_glue_map(records: &[Record]) -> HashMap<Name, Vec<IpAddr>> {
    let mut m: HashMap<Name, Vec<IpAddr>> = HashMap::new();
    for r in records {
        if let Some(ip @ IpAddr::V4(_)) = record_ip(r) {
            m.entry(r.name().clone()).or_default().push(ip);
        }
    }
    m
}

async fn chain_walk(
    name: Name,
    qtype: RecordType,
    rng: &mut Rng,
    depth: u32,
) -> Result<ChainResult, Box<dyn std::error::Error + Send + Sync>> {
    if depth > MAX_DEPTH {
        return Err(format!("max recursion depth {MAX_DEPTH} exceeded").into());
    }

    let mut roots: Vec<(String, SocketAddr)> = ROOT_SERVERS
        .iter()
        .map(|(label, octets)| {
            let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            (
                format!("{label}.root-servers.net"),
                SocketAddr::new(IpAddr::V4(ip), 53),
            )
        })
        .collect();
    rng.shuffle(&mut roots);

    let mut current_candidates = roots;
    let mut steps: Vec<Step> = Vec::new();
    let mut visited: HashSet<SocketAddr> = HashSet::new();
    let mut last_referral_authority: Vec<Record> = Vec::new();
    let mut last_referral_additional: Vec<Record> = Vec::new();
    let mut last_referral_label: String = String::from("(none)");

    loop {
        if steps.len() >= MAX_HOPS {
            return Err(format!("max hops {MAX_HOPS} exceeded").into());
        }

        let mut chosen: Option<(String, SocketAddr, DnsResp)> = None;
        let mut skipped: Vec<(String, SocketAddr, String)> = Vec::new();

        for (label, addr) in &current_candidates {
            if visited.contains(addr) {
                skipped.push((label.clone(), *addr, "already visited".into()));
                continue;
            }
            match timeout(QUERY_TIMEOUT, query(*addr, name.clone(), qtype)).await {
                Ok(Ok(resp)) => {
                    visited.insert(*addr);
                    chosen = Some((label.clone(), *addr, resp));
                    break;
                }
                Ok(Err(e)) => skipped.push((label.clone(), *addr, format!("error: {e}"))),
                Err(_) => skipped.push((label.clone(), *addr, "timeout".into())),
            }
        }

        let (server_label, server_addr, resp) = match chosen {
            Some(t) => t,
            None => return Err("all candidates failed at this hop".into()),
        };

        let answers_present = !resp.answers.is_empty();

        if answers_present {
            steps.push(Step {
                server_label: server_label.clone(),
                server_addr,
                qname: name.clone(),
                qtype,
                rcode: resp.rcode,
                aa: resp.aa,
                answers: resp.answers.clone(),
                authority: resp.authority.clone(),
                additional: resp.additional.clone(),
                skipped,
                sub: Vec::new(),
            });
            return Ok(ChainResult {
                steps,
                parent_ns: extract_ns_names(&last_referral_authority),
                parent_glue: last_referral_additional,
                apex_answer: resp.answers,
                auth_label: server_label,
                parent_label: last_referral_label,
            });
        }

        let ns_names = extract_ns_names(&resp.authority);
        if ns_names.is_empty() {
            steps.push(Step {
                server_label: server_label.clone(),
                server_addr,
                qname: name.clone(),
                qtype,
                rcode: resp.rcode,
                aa: resp.aa,
                answers: resp.answers,
                authority: resp.authority,
                additional: resp.additional,
                skipped,
                sub: Vec::new(),
            });
            return Err(format!(
                "{server_label} returned no answer and no NS records (rcode={:?})",
                steps.last().unwrap().rcode
            )
            .into());
        }

        let glue_map = build_glue_map(&resp.additional);
        let mut next_candidates: Vec<(String, SocketAddr)> = Vec::new();
        for ns_name in &ns_names {
            if let Some(ips) = glue_map.get(ns_name) {
                for ip in ips {
                    next_candidates.push((ns_name.to_string(), SocketAddr::new(*ip, 53)));
                }
            }
        }

        let mut sub_chains: Vec<(Name, Vec<Step>)> = Vec::new();
        if next_candidates.is_empty() {
            for ns_name in &ns_names {
                let result =
                    Box::pin(chain_walk(ns_name.clone(), RecordType::A, rng, depth + 1)).await;
                match result {
                    Ok(sub) => {
                        let ip_opt = sub
                            .apex_answer
                            .iter()
                            .find_map(|r| match r.data() {
                                RData::A(a) => Some(IpAddr::V4(a.0)),
                                _ => None,
                            });
                        sub_chains.push((ns_name.clone(), sub.steps));
                        if let Some(ip) = ip_opt {
                            next_candidates.push((
                                ns_name.to_string(),
                                SocketAddr::new(ip, 53),
                            ));
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        rng.shuffle(&mut next_candidates);

        last_referral_authority = resp.authority.clone();
        last_referral_additional = resp.additional.clone();
        last_referral_label = server_label.clone();

        steps.push(Step {
            server_label,
            server_addr,
            qname: name.clone(),
            qtype,
            rcode: resp.rcode,
            aa: resp.aa,
            answers: resp.answers,
            authority: resp.authority,
            additional: resp.additional,
            skipped,
            sub: sub_chains,
        });

        if next_candidates.is_empty() {
            return Err("could not resolve any next-hop NS to an IP".into());
        }
        current_candidates = next_candidates;
    }
}

async fn poll_auths(
    name: &Name,
    qtype: RecordType,
    chain: &ChainResult,
    apex_ns: &[Name],
    rng: &mut Rng,
) {
    if apex_ns.is_empty() {
        println!("(no apex NS records returned; nothing to poll)");
        return;
    }

    let mut ip_map: HashMap<Name, Vec<IpAddr>> = HashMap::new();
    for r in chain.steps.last().map(|s| s.additional.as_slice()).unwrap_or(&[]) {
        if let Some(ip @ IpAddr::V4(_)) = record_ip(r) {
            ip_map.entry(r.name().clone()).or_default().push(ip);
        }
    }
    for r in &chain.parent_glue {
        if let Some(ip @ IpAddr::V4(_)) = record_ip(r) {
            ip_map.entry(r.name().clone()).or_default().push(ip);
        }
    }

    let mut sorted_ns: Vec<Name> = apex_ns.to_vec();
    sorted_ns.sort();

    for ns_name in &sorted_ns {
        let ips: Vec<IpAddr> = match ip_map.get(ns_name) {
            Some(v) => {
                let mut v = v.clone();
                v.sort();
                v.dedup();
                v
            }
            None => match Box::pin(chain_walk(ns_name.clone(), RecordType::A, rng, 1)).await {
                Ok(sub) => sub
                    .apex_answer
                    .iter()
                    .filter_map(|r| match r.data() {
                        RData::A(a) => Some(IpAddr::V4(a.0)),
                        _ => None,
                    })
                    .collect(),
                Err(e) => {
                    println!("[{ns_name}] could not resolve NS address: {e}");
                    println!();
                    continue;
                }
            },
        };

        if ips.is_empty() {
            println!("[{ns_name}] no IPs available");
            println!();
            continue;
        }

        let mut shuffled = ips.clone();
        rng.shuffle(&mut shuffled);

        let mut answered = false;
        let mut errors: Vec<String> = Vec::new();
        for ip in &shuffled {
            let addr = SocketAddr::new(*ip, 53);
            match timeout(QUERY_TIMEOUT, query(addr, name.clone(), qtype)).await {
                Ok(Ok(resp)) => {
                    print_auth_response(ns_name, addr, qtype, &resp);
                    answered = true;
                    break;
                }
                Ok(Err(e)) => errors.push(format!("{addr}: error: {e}")),
                Err(_) => errors.push(format!("{addr}: timeout")),
            }
        }
        if !answered {
            println!("[{ns_name}] all addresses failed:");
            for e in &errors {
                println!("  {e}");
            }
        }
        println!();
    }
}

fn print_auth_response(ns_name: &Name, addr: SocketAddr, qtype: RecordType, resp: &DnsResp) {
    let aa = if resp.aa { " AA" } else { "" };
    println!("[{ns_name} {addr}] {qtype} rcode={:?}{aa}", resp.rcode);
    if !resp.answers.is_empty() {
        for r in &resp.answers {
            println!("  {r}");
        }
    } else {
        println!("  (no answer)");
        for r in &resp.authority {
            if matches!(r.data(), RData::SOA(_)) {
                println!("  SOA: {r}");
            }
        }
    }
}

fn classify_step(s: &Step) -> &'static str {
    if !s.answers.is_empty() {
        "ANSWER"
    } else if s.authority.iter().any(|r| matches!(r.data(), RData::NS(_))) {
        "referral"
    } else {
        "no-data"
    }
}

fn print_query_trace(steps: &[Step]) {
    println!("queries made ({}):", steps.len());
    for (i, s) in steps.iter().enumerate() {
        let aa = if s.aa { " AA" } else { "" };
        let kind = classify_step(s);
        println!(
            "  {i}. {} ({}) -> {} rcode={:?}{aa}",
            s.server_label, s.server_addr, kind, s.rcode
        );
        for (label, addr, why) in &s.skipped {
            println!("       fallback past {label} ({addr}): {why}");
        }
    }
}

fn print_steps(steps: &[Step], indent: usize) {
    let pad = " ".repeat(indent);
    for (i, s) in steps.iter().enumerate() {
        let aa = if s.aa { " AA" } else { "" };
        println!(
            "{pad}[{i}] queried {} ({}) for {} {}  rcode={:?}{aa}",
            s.server_label, s.server_addr, s.qname, s.qtype, s.rcode
        );
        for (label, addr, why) in &s.skipped {
            println!("{pad}    (failed over from {label} {addr}: {why})");
        }
        if !s.answers.is_empty() {
            println!("{pad}  ANSWER (records returned by this server):");
            for r in &s.answers {
                println!("{pad}    {r}");
            }
        }
        if !s.authority.is_empty() {
            println!(
                "{pad}  AUTHORITY (referral list returned by this server, not queried):"
            );
            for r in &s.authority {
                println!("{pad}    {r}");
            }
        }
        if !s.additional.is_empty() {
            println!(
                "{pad}  ADDITIONAL (glue records returned by this server, not queried):"
            );
            for r in &s.additional {
                println!("{pad}    {r}");
            }
        }
        for (ns, sub_steps) in &s.sub {
            println!("{pad}  -- no glue for {ns}, resolving from root --");
            print_steps(sub_steps, indent + 4);
        }
        println!();
    }
}
