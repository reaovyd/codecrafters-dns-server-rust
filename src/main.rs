// Uncomment this block to pass the first stage
// use std::net::UdpSocket;

use std::net::UdpSocket;

use dns_starter_rust::{DnsHeader, OpCode, RecursionDesired, ResponseCode};

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    // println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                if size < 12 {
                    let err_msg =
                        format!("Invalid number of bytes for received packet; received {size}\n");
                    if let Err(msg) = udp_socket.send_to(err_msg.as_bytes(), source) {
                        println!("Failed to send message response; received {msg}");
                    }
                } else {
                    let header = DnsHeader::new(
                        1234,
                        dns_starter_rust::QrIndicator::Reply,
                        OpCode::Query,
                        dns_starter_rust::AuthAnswer::NotAuthoritative,
                        dns_starter_rust::Truncation::NotTruncated,
                        RecursionDesired::NoRecursion,
                        dns_starter_rust::RecursionStatus::NotAvailable,
                        0,
                        ResponseCode::NoError,
                        0,
                        0,
                        0,
                        0,
                    );
                    let hdr = <[u8; 12]>::from(header);
                    if let Err(msg) = udp_socket.send_to(&hdr, source) {
                        println!("Failed to send message response; received {msg}");
                    }
                }
                // (0..size).for_each(|i| {
                //     println!("{:?}", buf[i]);
                // });
                // let received_data = String::from_utf8_lossy(&buf[0..size]);
                // println!("{size} {:?}", received_data);
                // let response = [];
                // udp_socket
                //     .send_to(&response, source)
                //     .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
