use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::checksum;
use rand::Rng;
use std::net::Ipv4Addr;
use std::time::Duration;

// 创建 TCP 数据包
fn create_tcp_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut ethernet_frame_buffer = vec![0u8; 14 + 20 + 20 + payload.len()];

    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_frame_buffer).unwrap();
    ethernet_packet.set_source(src_mac.into());
    ethernet_packet.set_destination(dst_mac.into());
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length((20 + 20 + payload.len()) as u16);
    ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_checksum(0);
    ipv4_packet.set_checksum(checksum(&ipv4_packet.packet(), 2));

    let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(seq_num);
    tcp_packet.set_acknowledgement(ack_num);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(flags);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_payload(payload);

    tcp_packet.set_checksum(0);
    let pseudo_header =
        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
    tcp_packet.set_checksum(pseudo_header);

    ethernet_frame_buffer
}

// 发送数据包
fn send_packet(interface_name: &str, packet: &[u8]) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .expect("Network interface not found");

    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _)) => (tx, ()),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    tx.send_to(packet, None)
        .expect("Failed to send Ethernet frame");
}

// 专用于三次握手和控制包接收
fn listen_for_handshake(
    interface_name: &str,
    src_port: u16,
    dst_port: u16,
) -> Option<(u32, u32, u8)> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .expect("Network interface not found");

    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    let timeout = Duration::from_secs(5); // Timeout after 5 seconds
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < timeout {
        if let Ok(packet) = rx.next() {
            let eth_packet = EthernetPacket::new(packet).unwrap();

            if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();

                if ipv4_packet.get_next_level_protocol()
                    == pnet::packet::ip::IpNextHeaderProtocols::Tcp
                {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();

                    if tcp_packet.get_source() == dst_port
                        && tcp_packet.get_destination() == src_port
                    {
                        return Some((
                            tcp_packet.get_sequence(),
                            tcp_packet.get_acknowledgement(),
                            tcp_packet.get_flags(),
                        ));
                    }
                }
            }
        }
    }

    println!("Timeout waiting for handshake packet.");
    None
}

// 专用于接收完整 HTTP 响应
fn listen_for_response(interface_name: &str, src_port: u16, dst_port: u16) -> Vec<u8> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .expect("Network interface not found");

    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    let mut full_response = Vec::new();
    let timeout = Duration::from_secs(5);
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < timeout {
        if let Ok(packet) = rx.next() {
            let eth_packet = EthernetPacket::new(packet).unwrap();

            if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();

                if ipv4_packet.get_next_level_protocol()
                    == pnet::packet::ip::IpNextHeaderProtocols::Tcp
                {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();

                    if tcp_packet.get_source() == dst_port
                        && tcp_packet.get_destination() == src_port
                    {
                        full_response.extend_from_slice(tcp_packet.payload());

                        // 如果收到 FIN 包，则结束接收
                        if tcp_packet.get_flags() & TcpFlags::FIN != 0 {
                            println!("Received FIN from server, ending response collection.");
                            break;
                        }
                    }
                }
            }
        }
    }

    if full_response.is_empty() {
        println!("Timeout waiting for response or no data received.");
    }

    full_response
}

fn main() {
    // 配置网络信息
    let src_mac = [0xf8, 0x9e, 0x94, 0xf2, 0x30, 0x4b];
    let dst_mac = [0x00, 0x00, 0x5e, 0x00, 0x01, 0x01];
    let src_ip = "10.20.100.119".parse::<Ipv4Addr>().unwrap();
    let dst_ip = "93.184.215.14".parse::<Ipv4Addr>().unwrap();
    // let src_port = 12345;
    let src_port = rand::thread_rng().gen_range(1024..65535);
    let dst_port = 80;

    // 三次握手
    let seq_num = 0x12345678;
    let ack_num = 0;
    let syn_packet = create_tcp_packet(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq_num,
        ack_num,
        TcpFlags::SYN,
        b"",
    );
    send_packet(
        "\\Device\\NPF_{A884DA93-96DC-41FC-A059-4B79F6B3131E}",
        &syn_packet,
    );
    println!("SYN packet sent.");

    if let Some((server_seq, _, flags)) = listen_for_handshake(
        "\\Device\\NPF_{A884DA93-96DC-41FC-A059-4B79F6B3131E}",
        src_port,
        dst_port,
    ) {
        if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
            println!("Received SYN-ACK.");
            let ack_packet = create_tcp_packet(
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq_num + 1,
                server_seq + 1,
                TcpFlags::ACK,
                b"",
            );
            send_packet(
                "\\Device\\NPF_{A884DA93-96DC-41FC-A059-4B79F6B3131E}",
                &ack_packet,
            );
            println!("ACK sent, three-way handshake complete.");

            // 发送 HTTP 请求
            let http_request =
                b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n";
            let http_request_packet = create_tcp_packet(
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq_num + 1,
                server_seq + 1,
                TcpFlags::PSH | TcpFlags::ACK,
                http_request,
            );
            send_packet(
                "\\Device\\NPF_{A884DA93-96DC-41FC-A059-4B79F6B3131E}",
                &http_request_packet,
            );
            println!("HTTP request sent.");

            // 接收 HTTP 响应
            let response_payload = listen_for_response(
                "\\Device\\NPF_{A884DA93-96DC-41FC-A059-4B79F6B3131E}",
                src_port,
                dst_port,
            );
            if !response_payload.is_empty() {
                println!("Received HTTP response:");
                println!("{}", String::from_utf8_lossy(&response_payload));
            } else {
                println!("No response received or response was empty.");
            }
        }
    }
}
