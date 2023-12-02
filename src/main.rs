use std::net::UdpSocket;

use dns_starter_rust::{
    buffer::{UdpBuffer, MAX_UDP_PACKET_SIZE},
    header::{
        AuthAnswer, DnsHeader, HeaderSecondRowFirstHalf, HeaderSecondRowSecondHalf, OpCode,
        QueryResponse, RecursionAvailablity, ResponseCode, SectionCount, Truncation,
    },
    section::Section,
};
use nom::AsBytes;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; MAX_UDP_PACKET_SIZE];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_size, _source)) => {
                let udp_buf = UdpBuffer::new(buf);
                match udp_buf.unpack() {
                    Ok((header, [qsection, _ansection, _nssection, _arsection])) => {
                        match qsection {
                            Some(qsection) => {
                                let qsection_raw = qsection.raw_domain;
                                let mut groups = Vec::new();
                                let mut asection_raw = Vec::new();
                                for group in qsection.groups {
                                    let mut new_group = group.clone();
                                    new_group.asection =
                                        Some((444, 4, vec![0x12, 0x34, 0x56, 0x78]));
                                    asection_raw.append(
                                        &mut Vec::<u8>::try_from(new_group.clone()).unwrap(),
                                    );
                                    groups.push(new_group);
                                }
                                let ancount = groups.len() as u16;
                                let res_asection = Section::new(groups, asection_raw);
                                let out_header = DnsHeader::new(
                                    header.txid(),
                                    HeaderSecondRowFirstHalf::new(
                                        QueryResponse::Response,
                                        header.header_first_half().opcode().clone(),
                                        AuthAnswer::NotAuthoritative,
                                        Truncation::NotTruncated,
                                        header.header_first_half().rd().clone(),
                                    ),
                                    HeaderSecondRowSecondHalf::new(
                                        RecursionAvailablity::NoRecursionAvailable,
                                        0,
                                        match header.header_first_half().opcode() {
                                            OpCode::Query => ResponseCode::None,
                                            _ => ResponseCode::NotImplemented,
                                        },
                                    )
                                    .expect(
                                        "if it fails, then reserved was something larger than expected...",
                                    ),
                                    SectionCount::new(
                                        header.counts().qdcount(),
                                        ancount,
                                        0,
                                        0,
                                    ),
                                );
                                let mut res = <[u8; 12]>::from(out_header).to_vec();
                                res.extend(qsection_raw);
                                res.extend(res_asection.raw_domain);
                                println!("{:?}", res);
                                if let Err(msg) = udp_socket.send_to(res.as_bytes(), _source) {
                                    eprintln!("error sending message! {msg}")
                                }
                            }
                            None => {
                                eprintln!("Error parsing; missing qsection!");
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("Error parsing; {err}");
                    }
                }
            }
            Err(err) => {
                eprintln!("Error parsing; {err}");
            }
        }
    }

    // loop {
    //     match udp_socket.recv_from(&mut buf) {
    //         Ok((size, source)) => {
    //             if size < 12 {
    //                 let err_msg =
    //                     format!("Invalid number of bytes for received packet; received {size}\n");
    //                 if let Err(msg) = udp_socket.send_to(err_msg.as_bytes(), source) {
    //                     eprintln!("Failed to send message response; received {msg}");
    //                 }
    //             } else {
    //                 match DnsHeader::try_from(&buf[0..12]) {
    //                     Ok(hdr) => {
    //                         println!("{:?}", buf);
    //                         if let Some(payload) = &buf.get(12..) {
    //                             println!("{:?}", payload);
    //                             println!("{:?}", String::from_utf8_lossy(payload));
    //                             match hdr.qr() {
    //                                 QrIndicator::Question => {
    //                                     // TODO: https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
    //                                     let qdcount = hdr.qdcount().to_owned();
    //                                     let ancount = hdr.ancount().to_owned();
    //                                     if let Ok((qsections, _asections)) =
    //                                         parse_all_sections(payload, qdcount, ancount)
    //                                     {
    //                                         let mut asections = Vec::new();
    //                                         let mut ancount = 0;
    //                                         qsections.iter().for_each(|elem| {
    //                                             let mut bytes = ASection::new(
    //                                                 elem.section().to_owned(),
    //                                                 (0x000000FF, [0x00, 0x00, 0x00, 0xFF]),
    //                                                 (0x0004, [0x00, 0x04]),
    //                                                 vec![76, 76, 21, 21],
    //                                             )
    //                                             .into_bytes();
    //                                             ancount += 1;
    //                                             asections.append(&mut bytes);
    //                                         });
    //                                         let mut qsections = qsections.into_iter().fold(
    //                                             Vec::<u8>::new(),
    //                                             |mut acc: Vec<u8>, elem| {
    //                                                 elem.into_bytes().into_iter().for_each(
    //                                                     |byte| {
    //                                                         acc.push(byte);
    //                                                     },
    //                                                 );
    //                                                 acc
    //                                             },
    //                                         );

    //                                         let mut res = <[u8; 12]>::from(DnsHeader::new(
    //                                             hdr.id().to_owned(),
    //                                             QrIndicator::Reply,
    //                                             hdr.opcode().to_owned(),
    //                                             AuthAnswer::NotAuthoritative,
    //                                             Truncation::NotTruncated,
    //                                             hdr.recursion_desired().to_owned(),
    //                                             RecursionStatus::NotAvailable,
    //                                             0,
    //                                             match hdr.opcode() {
    //                                                 OpCode::Query => ResponseCode::NoError,
    //                                                 _ => ResponseCode::NotImplemented,
    //                                             },
    //                                             *hdr.qdcount(),
    //                                             ancount,
    //                                             0,
    //                                             0,
    //                                         ))
    //                                         .to_vec();

    //                                         res.append(&mut qsections);
    //                                         res.append(&mut asections);
    //                                         if let Err(err_msg) = udp_socket.send_to(&res, source) {
    //                                             eprintln!("Error sending message; got {err_msg}");
    //                                         }
    //                                     } else {
    //                                         eprintln!(
    //                                             "Error parsing; not enough bytes for the header!"
    //                                         );
    //                                     }
    //                                 }
    //                                 QrIndicator::Reply => todo!(),
    //                             }
    //                         } else {
    //                             eprintln!("Error parsing; not enough bytes for the header!");
    //                         }
    //                     }
    //                     Err(msg) => {
    //                         eprintln!("{:?}", &buf[0..12]);
    //                         eprintln!("Error parsing; header could not be parsed! {msg}");
    //                     }
    //                 }
    //             }
    //         }
    //         Err(e) => {
    //             eprintln!("Error receiving data: {}", e);
    //             break;
    //         }
    //     }
    // }
}
