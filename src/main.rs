use std::io;

use pnet::packet::ip;

fn main() -> io::Result<()> {
    // Create a new TUN interface named "tun0" in TUN mode.
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;

    // Define a buffer of size 1504 bytes (maximum Ethernet frame size without CRC) to store received data.
    let mut buf = [0u8; 1504];

    // Main loop to continuously receive data from the interface.
    loop {
        // Receive data from the TUN interface and store the number of bytes received in `nbytes`.

        let nbytes = nic.recv(&mut buf[..])?;
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        eprintln!("read {} bytes: {:x?}", nbytes - 4, &buf[4..nbytes]);

        if proto != 0x0800 {
            
            continue;
        }

        // Attempt to parse an IPv4 header from the provided buffer slice.
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            // If the parsing was successful, proceed with the parsed packet.
            Ok(iph) => {
                // Extract the source IP address from the parsed packet.
                let src = iph.source_addr();

                // Extract the destination IP address from the parsed packet.
                let dst = iph.destination_addr();

                // Extract the protocol number from the parsed packet.
                // For TCP, this number is typically 6 (0x06).
                let proto = iph.protocol();

                // Check if the protocol number is not TCP (0x06).
                if proto != 0x06 {
                    // If the packet is not a TCP packet, skip further processing.
                    continue;
                }

                // Attempt to parse the TCP header from the buffer slice.
                // Here, we adjust the starting slice based on the length of the IPv4 header.
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + iph.slice().len()..]) {
                    // If TCP header parsing was successful, proceed.
                    Ok(tcph) => {
                        // Print the details: Source IP, Destination IP, and the Destination Port.
                        eprintln!(
                            "{} -> {}: TCP to port {}",
                            src,
                            dst,
                            tcph.destination_port()
                        );
                    }
                    // Handle potential errors while parsing the TCP header.
                    Err(e) => {
                        eprintln!("An error occurred while parsing TCP packet: {:?}", e);
                    }
                }
            }
            // Handle potential errors while parsing the IPv4 header.
            Err(e) => {
                eprintln!("An error occurred while parsing IP packet: {:?}", e);
            }
        }
    }

    Ok(())
}

// setei o ip sudo ip addr add 192.168.0.1/24 dev tun0

/*

#!/bin/bash
PKG_NAME=tcp
cargo b --release
sudo setcap cap_net_admin=eip target/release/$PKG_NAME
./target/release/$PKG_NAME &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid




*/
// tcp.rs
// Defining possible TCP states. 
// Each state represents a specific stage in the TCP connection.
pub enum State { 
    // The connection is closed and no active connection exists. 
    Closed, 
    // The endpoint is waiting for a connection attempt from a remote endpoint. 
    Listen, 
    /// The endpoint has received a SYN (synchronize) segment and has sent a SYN-ACK /// (synchronize-acknowledgment) segment in response. It is awaiting an ACK (acknowledgment) /// segment from the remote endpoint. 
    SynRcvd, 
    // The connection is established, and both endpoints can send and receive data. Estab, 
    }
    
    
    // Implementing the Default trait for State. // Sets the default TCP state to 'Listen'. 
    impl Default for State { 
        fn default() -> Self { 
            State::Listen 
        } 
    }
    
    // Implementing methods for State. 
    impl State {
    // Method to handle incoming TCP packets. 
    // 'iph' contains the parsed IPv4 header, 'tcph' contains the parsed TCP header, and 'data' contains the TCP payload. 
    pub fn on_packet<'a>( 
        &mut self, 
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        tcph: etherparse::TcpHeaderSlice<'a>, 
        data: &'a [u8], 
        ) { 
        // Log the source and destination IP addresses and ports, as well as the payload length. 
            eprintln!( 
                "{}:{} -> {}:{} {}b of TCP", 
                iph.source_addr(), 
                tcph.source_port(), 
                iph.destination_addr(), 
                tcph.destination_port(), 
                data.len() 
            ); 
        } 
    }