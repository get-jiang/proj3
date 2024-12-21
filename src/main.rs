use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::checksum;
use rand::Rng;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

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

fn send_packet(tx: &mut Box<dyn pnet::datalink::DataLinkSender>, packet: &[u8]) {
    tx.send_to(packet, None)
        .expect("Failed to send Ethernet frame");
}

fn listen_for_response(
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>,
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    mut ack_num: u32,
) -> Vec<u8> {
    let init_ack_num = ack_num;
    let mut received_data = BTreeMap::new(); // 用于存储接收到的数据包（按序列号排序）
    let timeout = Duration::from_secs(100);
    let start_time = std::time::Instant::now();
    while start_time.elapsed() < timeout {
        if let Ok(packet) = rx.next() {
            let eth_packet = EthernetPacket::new(packet).unwrap();

            if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                let ipv4_packet = match Ipv4Packet::new(eth_packet.payload()) {
                    Some(packet) => packet,
                    None => continue,
                };

                if ipv4_packet.get_next_level_protocol()
                    == pnet::packet::ip::IpNextHeaderProtocols::Tcp
                {
                    let tcp_packet = match TcpPacket::new(ipv4_packet.payload()) {
                        Some(packet) => packet,
                        None => continue,
                    };

                    if tcp_packet.get_source() == dst_port
                        && tcp_packet.get_destination() == src_port
                    {
                        let seq = tcp_packet.get_sequence();
                        let payload = tcp_packet.payload();

                        // 保存收到的数据包（仅存储非空负载）
                        if !payload.is_empty() {
                            received_data.insert(seq, payload.to_vec());
                            println!("Received data packet with seq {}.", seq);
                        }

                        // 回复 ACK
                        if ack_num == seq {
                            ack_num = seq + payload.len() as u32;
                            let ack_packet = create_tcp_packet(
                                src_mac,
                                dst_mac,
                                src_ip,
                                dst_ip,
                                src_port,
                                dst_port,
                                seq_num,
                                ack_num,
                                TcpFlags::ACK,
                                b"",
                            );
                            send_packet(tx, &ack_packet);
                        }

                        // 检查是否收到 PSH 包，并进行数据完整性检查
                        if tcp_packet.get_flags() & TcpFlags::PSH != 0 {
                            let expected_end_seq = tcp_packet.get_sequence();
                            println!("PSH flag received. Checking data integrity.");
                            if is_data_complete(&received_data, init_ack_num, expected_end_seq) {
                                println!("All expected data received. Ending response collection.");
                                break;
                            } else {
                                println!("Data incomplete. Waiting for missing packets.");
                            }
                        }
                    }
                }
            }
        }
    }

    // 按序列号排序并拼接完整响应
    let mut full_response = Vec::new();
    for payload in received_data.values() {
        full_response.extend_from_slice(payload);
    }

    if full_response.is_empty() {
        println!("Timeout or no response received.");
    }

    full_response
}

// 检查数据是否齐全的函数
fn is_data_complete(
    received_data: &BTreeMap<u32, Vec<u8>>,
    start_seq: u32,
    expected_end_seq: u32,
) -> bool {
    let mut current_seq = start_seq;

    for (&seq, payload) in received_data {
        if seq == current_seq {
            current_seq += payload.len() as u32; // 数据连续，更新当前序列号
        } else {
            println!(
                "Missing data: expected seq {}, but found seq {}.",
                current_seq, seq
            );
            return false; // 数据不连续，返回不完整
        }
    }

    if current_seq >= expected_end_seq {
        true // 数据齐全
    } else {
        println!(
            "Data incomplete: current_seq is {}, but expected_end_seq is {}.",
            current_seq, expected_end_seq
        );
        false
    }
}

fn listen_for_ack(
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
) -> Option<u32> {
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
                        && tcp_packet.payload().is_empty()
                    {
                        assert!(
                            tcp_packet.get_sequence() == seq_num
                                && tcp_packet.get_acknowledgement() == ack_num
                        );
                        println!("init seq: {}", tcp_packet.get_sequence());
                        return Some(tcp_packet.get_sequence());
                    }
                }
            }
        }
    }

    None
}

fn listen_for_handshake(
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>,
    src_port: u16,
    dst_port: u16,
) -> Option<(u32, u32, u8)> {
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

    None
}

fn main() {
    let src_mac = [0xf8, 0x9e, 0x94, 0xf2, 0x30, 0x4b];
    let dst_mac = [0x00, 0x00, 0x5e, 0x00, 0x01, 0x01];
    let src_ip = "10.20.100.119".parse::<Ipv4Addr>().unwrap();
    let dst_ip = "148.135.81.197".parse::<Ipv4Addr>().unwrap();
    let src_port = rand::thread_rng().gen_range(1024..65535);
    let dst_port = 80;

    let interface_name = "\\Device\\NPF_{A884DA93-96DC-41FC-A059-4B79F6B3131E}";
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .expect("Network interface not found");

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    let mut my_seq_num = 0x12345678;
    let mut my_ack_num = 0;
    //三次握手
    //1
    let syn_packet = create_tcp_packet(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        my_seq_num,
        my_ack_num,
        TcpFlags::SYN,
        b"",
    );

    send_packet(&mut tx, &syn_packet);
    println!("SYN packet sent.");
    //2
    if let Some((server_seq, _, flags)) = listen_for_handshake(&mut rx, src_port, dst_port) {
        if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
            println!("Received SYN-ACK.");
            //3
            my_ack_num = server_seq + 1;
            my_seq_num += 1;
            let ack_packet = create_tcp_packet(
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                my_seq_num,
                my_ack_num,
                TcpFlags::ACK,
                b"",
            );
            send_packet(&mut tx, &ack_packet);
            println!("ACK sent, three-way handshake complete.");
            //send http request
            let http_request = b"GET / HTTP/1.1\r\nHost: guozhi.vip\r\nConnection: close\r\n\r\n";
            let http_request_packet = create_tcp_packet(
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                my_seq_num,
                my_ack_num,
                TcpFlags::PSH | TcpFlags::ACK,
                http_request,
            );
            send_packet(&mut tx, &http_request_packet);
            my_seq_num += http_request.len() as u32;
            println!("HTTP request sent.");
            //receive http response
            if let Some(start_seq) =
                listen_for_ack(&mut rx, src_port, dst_port, my_ack_num, my_seq_num)
            {
                //receive http data
                let response_payload = listen_for_response(
                    &mut rx, &mut tx, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                    my_seq_num, my_ack_num,
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
}
