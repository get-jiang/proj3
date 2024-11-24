use pcap::Capture;
use std::ptr::null_mut;

use std::net::Ipv4Addr;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{FARPROC, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

fn main() {
    use std::sync::Arc;

    //Must be run as Administrator because we create network adapters
    //Load the wintun dll file so that we can call the underlying C functions
    //Unsafe because we are loading an arbitrary dll file
    let wintun =
        unsafe { wintun::load_from_path("wintun.dll") }.expect("Failed to load wintun dll");

    //Try to open an adapter with the name "Demo"
    let adapter = match wintun::Adapter::open(&wintun, "Demo") {
        Ok(a) => a,
        Err(_) => {
            println!("Failed to open wintun adapter, creating a new one");
            //If loading failed (most likely it didn't exist), create a new one
            wintun::Adapter::create(&wintun, "Demo", "Example", None)
                .expect("Failed to create wintun adapter!")
        }
    };
    //Specify the size of the ring buffer the wintun driver should use.
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());

    //Get a 20 byte packet from the ring buffer
    loop {
        println!("Sending packet");
        let mut packet = session.allocate_send_packet(12).unwrap();
        let bytes: &mut [u8] = packet.bytes_mut();
        //Write IPV4 version and header length
        bytes[0] = 0x40;

        //Finish writing IP header
        bytes[9] = 0x69;
        bytes[10] = 0x04;
        bytes[11] = 0x20;
        //Send the packet to wintun virtual adapter for processing by the system
        session.send_packet(packet);
    }
    //Stop any readers blocking for data on other threads
    //Only needed when a blocking reader is preventing shutdown Ie. it holds an Arc to the
    //session, blocking it from being dropped
    // session.shutdown();

    //the session is stopped on drop
    //drop(session);

    //drop(adapter)
    //And the adapter closes its resources when dropped
    // 后续操作：读写适配器的网络流量...
}

fn send_ping() {
    // 替换为你的网卡设备名
    let device_name = "\\Device\\NPF_{A884DA93-96DC-41FC-A059-4B79F6B3131E}";
    let mut cap = Capture::from_device(device_name).unwrap().open().unwrap();

    // 本机 MAC 地址（请替换为你的真实 MAC 地址）
    let src_mac = [0xf8, 0x9e, 0x94, 0xf2, 0x30, 0x4b];
    // 目标设备 MAC 地址（请替换为目标设备的 MAC 地址）
    let dst_mac = [0x00, 0x00, 0x5e, 0x00, 0x01, 0x01];

    // 本机 IP 地址
    let src_ip = Ipv4Addr::new(172, 18, 1, 1);
    // 目标设备 IP 地址（Ping 的目标地址）
    let dst_ip = Ipv4Addr::new(172, 18, 1, 2);

    // ICMP Echo 请求的初始序列号和标识符
    let identifier = 1;
    let sequence = 1;

    // 构造数据包
    let mut pktbuf = [0u8; 98];

    // Ethernet Header
    pktbuf[0..6].copy_from_slice(&dst_mac); // 目标 MAC 地址
    pktbuf[6..12].copy_from_slice(&src_mac); // 源 MAC 地址
    pktbuf[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // Ethertype: IPv4 (0x0800)

    // IP Header
    pktbuf[14] = 0x45; // IPv4, Header Length = 20 bytes
    pktbuf[15] = 0x00; // Type of Service
    pktbuf[16..18].copy_from_slice(&(84u16).to_be_bytes()); // Total Length (IP Header + ICMP)
    pktbuf[18..20].copy_from_slice(&0x0001u16.to_be_bytes()); // Identification
    pktbuf[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags and Fragment Offset
    pktbuf[22] = 64; // TTL (Time to Live)
    pktbuf[23] = 1; // Protocol: ICMP (1)
    pktbuf[24..26].copy_from_slice(&0u16.to_be_bytes()); // Header Checksum (暂时为 0)
    pktbuf[26..30].copy_from_slice(&src_ip.octets()); // Source IP
    pktbuf[30..34].copy_from_slice(&dst_ip.octets()); // Destination IP

    // IP Header 校验和
    let ip_checksum = checksum(&pktbuf[14..34]);
    pktbuf[24..26].copy_from_slice(&ip_checksum.to_be_bytes());

    // ICMP Header
    pktbuf[34] = 8; // ICMP Type: Echo Request (8)
    pktbuf[35] = 0; // Code: 0
    pktbuf[36..38].copy_from_slice(&0u16.to_be_bytes()); // ICMP 校验和（暂时为 0）
    pktbuf[38..40].copy_from_slice(&(identifier as u16).to_be_bytes()); // Identifier
    pktbuf[40..42].copy_from_slice(&(sequence as u16).to_be_bytes()); // Sequence Number

    // 填充 ICMP 数据部分
    for i in 42..98 {
        pktbuf[i] = i as u8;
    }

    // ICMP Header 校验和
    let icmp_checksum = checksum(&pktbuf[34..98]);
    pktbuf[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());

    // 发送数据包
    match cap.sendpacket(pktbuf) {
        Ok(_) => println!("ICMP Echo Request sent successfully!"),
        Err(e) => eprintln!("Failed to send ICMP Echo Request: {}", e),
    }
}

// 计算校验和
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let Some(&byte) = chunks.remainder().first() {
        sum += (byte as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
