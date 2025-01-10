use pnet::datalink::{self, NetworkInterface};
use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::io;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

lazy_static::lazy_static! {
    static ref TRAFFIC_STATS: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());W
}

const LOG_FILE: &str = "packet_log.txt";
const SUSPICIOUS_LOG: &str = "suspicious_log.txt";

fn log_packet(details: &str, file_path: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Unable to open log file");
    writeln!(file, "{}", details).expect("Unable to write to log file");
}

fn analyze_packet(packet: &[u8]) {
    if let Some(eth_packet) = EthernetPacket::new(packet) {
        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()) {
                    let src_ip = ipv4_packet.get_source();
                    let dst_ip = ipv4_packet.get_destination();

                    let mut stats = TRAFFIC_STATS.lock().unwrap();
                    let count = stats.entry(dst_ip.to_string()).or_insert(0);
                    *count += 1;

                    let log_entry = format!(
                        "Timestamp: {}, Src IP: {}, Dst IP: {}, Protocol: {:?}",
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_secs(),
                        src_ip,
                        dst_ip,
                        ipv4_packet.get_next_level_protocol()
                    );
                    log_packet(&log_entry, LOG_FILE);

                    if *count > 100 {
                        log_packet(&log_entry, SUSPICIOUS_LOG);
                    }

                    println!("{}", log_entry);

                    match ipv4_packet.get_next_level_protocol() {
                        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                println!(
                                    "TCP Packet: Src Port: {}, Dst Port: {}",
                                    tcp_packet.get_source(),
                                    tcp_packet.get_destination()
                                );
                            }
                        }
                        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                            if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                                println!(
                                    "UDP Packet: Src Port: {}, Dst Port: {}",
                                    udp_packet.get_source(),
                                    udp_packet.get_destination()
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

fn main() {

    let interfaces = datalink::interfaces();

    if interfaces.is_empty() {
        eprintln!("No network interfaces found!");
        return;
    }

    println!("Available network interfaces:");
    for (index, interface) in interfaces.iter().enumerate() {
        println!("{}: {} ({:?})", index, interface.name, interface.description);
    }

    /* For hard-coding the interface you want to monitor
    let interface_name = "\\Device\\NPF_{347370FB-CB51-43E5-A424-0021939F4203}";
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Specified network interface not found!");*/

        
    println!("\nEnter the number of the interface you want to monitor:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    
    let choice: usize = match input.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            eprintln!("Invalid input. Please enter a valid number.");
            return;
        }
    };    

    if choice >= interfaces.len() {
        eprintln!("Invalid selection. Please select a valid interface number.");
        return;
    }

    let interface = &interfaces[choice];
    println!(
        "Selected interface: {} ({:?})",
        interface.name, interface.description
    );

    println!("Selected interface: {:?}", interface);

    println!("Sniffing on interface: {}", interface.name);

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => analyze_packet(packet),
            Err(e) => eprintln!("Failed to read packet: {}", e),
        }
    }
}
