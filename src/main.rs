use std::net::UdpSocket;

use dns_starter_rust::{
    header_types::*,
    parser::section::{answer::ASection, parse_all_sections, Section, SectionBytes},
    DnsHeader,
};
use nom::AsBytes;

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
                } else if let Ok(hdr) = DnsHeader::try_from(&buf[0..12]) {
                    if let Some(payload) = &buf.get(12..) {
                        match hdr.qr() {
                            QrIndicator::Question => {
                                let qdcount = hdr.qdcount().to_owned();
                                let ancount = hdr.ancount().to_owned();
                                if let Ok((qsections, asections)) =
                                    parse_all_sections(payload, qdcount, ancount)
                                {
                                    let mut asections = Vec::new();
                                    qsections.iter().for_each(|elem| {
                                        let mut bytes = ASection::new(
                                            elem.section().to_owned(),
                                            (0x000000FF, [0x00, 0x00, 0x00, 0xFF]),
                                            (0x0004, [0x00, 0x04]),
                                            vec![76, 76, 21, 21],
                                        )
                                        .into_bytes();
                                        asections.append(&mut bytes);
                                    });

                                    let mut qsections = qsections.into_iter().fold(
                                        Vec::<u8>::new(),
                                        |mut acc: Vec<u8>, elem| {
                                            elem.into_bytes().into_iter().for_each(|byte| {
                                                acc.push(byte);
                                            });
                                            acc
                                        },
                                    );

                                    let mut res = <[u8; 12]>::from(DnsHeader::new(
                                        1234,
                                        QrIndicator::Reply,
                                        OpCode::Query,
                                        AuthAnswer::NotAuthoritative,
                                        Truncation::NotTruncated,
                                        RecursionDesired::NoRecursion,
                                        RecursionStatus::NotAvailable,
                                        0,
                                        ResponseCode::NoError,
                                        qdcount,
                                        qdcount,
                                        0,
                                        0,
                                    ))
                                    .to_vec();
                                    res.append(&mut qsections);
                                    res.append(&mut asections);
                                    if let Err(err_msg) = udp_socket.send_to(&res, source) {
                                        eprintln!("Error sending message; got {err_msg}");
                                    }
                                }
                            }
                            QrIndicator::Reply => todo!(),
                        }
                    } else {
                        println!("error parsing");
                    }
                } else {
                    println!("error parsing");
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
