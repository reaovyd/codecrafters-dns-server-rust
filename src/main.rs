use std::net::UdpSocket;

use dns_starter_rust::{
    header_types::*,
    parser::section::{answer::ASection, parse_all_sections, SectionBytes},
    DnsHeader,
};

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
                                if let Ok((qsections, _asections)) =
                                    parse_all_sections(payload, qdcount, ancount)
                                {
                                    let mut asections = Vec::new();
                                    let mut ancount = 0;
                                    qsections.iter().for_each(|elem| {
                                        let mut bytes = ASection::new(
                                            elem.section().to_owned(),
                                            (0x000000FF, [0x00, 0x00, 0x00, 0xFF]),
                                            (0x0004, [0x00, 0x04]),
                                            vec![76, 76, 21, 21],
                                        )
                                        .into_bytes();
                                        ancount += 1;
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
                                        hdr.id().to_owned(),
                                        QrIndicator::Reply,
                                        hdr.opcode().to_owned(),
                                        AuthAnswer::NotAuthoritative,
                                        Truncation::NotTruncated,
                                        hdr.recursion_desired().to_owned(),
                                        RecursionStatus::NotAvailable,
                                        0,
                                        match hdr.opcode() {
                                            OpCode::Query => ResponseCode::NoError,
                                            _ => ResponseCode::NotImplemented,
                                        },
                                        *hdr.qdcount(),
                                        ancount,
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
                        eprintln!("error parsing");
                    }
                } else {
                    eprintln!("error parsing");
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
