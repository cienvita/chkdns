use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
use std::str::FromStr;
use std::time::Duration;

use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::rr::{DNSClass, Name, RecordType};
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

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || args[1] == "-h" || args[1] == "--help" {
        eprintln!("usage: chkdns <domain>");
        process::exit(2);
    }
    let domain = &args[1];
    let name = match Name::from_str(domain) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("invalid domain '{domain}': {e}");
            process::exit(2);
        }
    };

    let mut handles = Vec::with_capacity(ROOT_SERVERS.len());
    for (label, octets) in ROOT_SERVERS {
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        let addr = SocketAddr::new(IpAddr::V4(ip), 53);
        let name = name.clone();
        let label = *label;
        handles.push(tokio::spawn(async move {
            let result = timeout(QUERY_TIMEOUT, query(addr, name)).await;
            (label, ip, result)
        }));
    }

    for h in handles {
        let (label, ip, result) = h.await.expect("task panicked");
        println!("== {label}.root-servers.net ({ip}) ==");
        match result {
            Err(_) => println!("  timeout after {QUERY_TIMEOUT:?}\n"),
            Ok(Err(e)) => println!("  error: {e}\n"),
            Ok(Ok(text)) => print!("{text}\n"),
        }
    }
}

async fn query(
    addr: SocketAddr,
    name: Name,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let connect = UdpClientStream::builder(addr, TokioRuntimeProvider::new()).build();
    let (mut client, bg) = Client::connect(connect).await?;
    let bg_handle = tokio::spawn(bg);

    let resp = client.query(name, DNSClass::IN, RecordType::NS).await?;
    bg_handle.abort();

    let mut out = String::new();
    let answers = resp.answers();
    let authority = resp.name_servers();
    let additional = resp.additionals();

    if !answers.is_empty() {
        out.push_str("  ANSWER:\n");
        for r in answers {
            out.push_str(&format!("    {r}\n"));
        }
    }
    if !authority.is_empty() {
        out.push_str("  AUTHORITY:\n");
        for r in authority {
            out.push_str(&format!("    {r}\n"));
        }
    }
    if !additional.is_empty() {
        out.push_str("  ADDITIONAL:\n");
        for r in additional {
            out.push_str(&format!("    {r}\n"));
        }
    }
    if out.is_empty() {
        out.push_str("  (empty response)\n");
    }
    Ok(out)
}
