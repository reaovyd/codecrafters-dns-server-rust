use std::{
    cell::RefCell,
    env,
    net::{SocketAddr, UdpSocket},
    rc::Rc,
    str::FromStr,
};

use dns_starter_rust::{
    buffer::{UdpBuffer, MAX_UDP_PACKET_SIZE},
    converter::{packet::PendingPacket, transcribe::Transcriber},
    header::{DnsHeader, QueryResponse},
};
use nom::AsBytes;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; MAX_UDP_PACKET_SIZE];
    let mut args: Vec<String> = env::args().collect();
    if args.len() != 3 || args.get(1).unwrap() != "--resolver" {
        panic!("{} --resolver <ip:port>", args.first().unwrap());
    }
    let address = args.swap_remove(2);
    let resolver_server = SocketAddr::from_str(&address).expect("Unable to parse socket address");
    let mut transcriber = Transcriber::default();

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_size, source)) => {
                let udp_buf = UdpBuffer::new(buf);
                match udp_buf.unpack() {
                    Ok((header, [qsection, ansection, _nssection, _arsection])) => {
                        match header.header_first_half().qr() {
                            QueryResponse::Query => {
                                if let Some(qsection) = qsection {
                                    println!(
                                        "query: {:?}, {:?}",
                                        header.txid(),
                                        transcriber.txid()
                                    );
                                    let pending_pkt = Rc::new(RefCell::new(PendingPacket::new(
                                        (
                                            source,
                                            header.txid(),
                                            header.header_first_half().opcode().to_owned(),
                                            header.header_first_half().rd().to_owned(),
                                        ),
                                        qsection.groups.len(),
                                        qsection.clone(),
                                    )));
                                    for group in qsection.groups {
                                        let mut hdr = <[u8; 12]>::from(DnsHeader::new(
                                            header.txid(),
                                            header.header_first_half().clone(),
                                            header.header_second_half().clone(),
                                            header.counts().clone(),
                                        ))
                                        .to_vec();
                                        match Vec::<u8>::try_from(group) {
                                            Ok(arr) => {
                                                hdr.extend(arr);
                                                let arr = hdr;
                                                if let Err(msg) = udp_socket
                                                    .send_to(arr.as_bytes(), resolver_server)
                                                {
                                                    eprintln!("Error sending; {msg}");
                                                } else {
                                                    transcriber.insert(Rc::clone(&pending_pkt))
                                                }
                                            }
                                            Err(msg) => {
                                                eprintln!("Error parsing; {msg}");
                                            }
                                        }
                                    }
                                } else {
                                    eprintln!("Couldn't get a qsection here...")
                                }
                            }
                            QueryResponse::Response => match ansection {
                                Some(ansection) => {
                                    println!("{:?}, {:?}", header.txid(), transcriber.txid());
                                    println!(
                                        "{:?}, {:?}, {:?}",
                                        ansection, source, resolver_server
                                    );
                                    for group in ansection.groups {
                                        match transcriber.receive_and_delete(header.txid(), group) {
                                            Some((pkt, source)) => {
                                                if let Err(msg) = udp_socket.send_to(
                                                    Vec::<u8>::from(pkt).as_bytes(),
                                                    source,
                                                ) {
                                                    eprintln!("{:?}", msg);
                                                }
                                            }
                                            None => {
                                                eprintln!("Not in one whole yet...")
                                            }
                                        }
                                    }
                                }
                                None => {
                                    eprintln!("Couldn't get a asection here...")
                                }
                            },
                        }
                    }
                    Err(err) => {
                        eprintln!("Error parsing; {err}")
                    }
                }
                // let (header, [qsection, ansection, nssection, arsection]) = udp_buf.unpack()
                // match udp_buf.unpack() {
                //     Ok((header, [qsection, _ansection, _nssection, _arsection])) => {
                //         match qsection {
                //             Some(qsection) => {
                //                 let qsection_raw = qsection.raw_domain;
                //                 let mut groups = Vec::new();
                //                 let mut asection_raw = Vec::new();
                //                 for group in qsection.groups {
                //                     let mut new_group = group.clone();
                //                     new_group.asection = Some((444, 4, vec![76, 76, 21, 21]));
                //                     asection_raw.append(
                //                         &mut Vec::<u8>::try_from(new_group.clone()).unwrap(),
                //                     );
                //                     groups.push(new_group);
                //                 }
                //                 let ancount = groups.len() as u16;
                //                 let res_asection = Section::new(groups, asection_raw);
                //                 let out_header = DnsHeader::new(
                //                     header.txid(),
                //                     HeaderSecondRowFirstHalf::new(
                //                         QueryResponse::Response,
                //                         header.header_first_half().opcode().clone(),
                //                         AuthAnswer::NotAuthoritative,
                //                         Truncation::NotTruncated,
                //                         header.header_first_half().rd().clone(),
                //                     ),
                //                     HeaderSecondRowSecondHalf::new(
                //                         RecursionAvailablity::NoRecursionAvailable,
                //                         0,
                //                         match header.header_first_half().opcode() {
                //                             OpCode::Query => ResponseCode::None,
                //                             _ => ResponseCode::NotImplemented,
                //                         },
                //                     )
                //                     .expect(
                //                         "if it fails, then reserved was something larger than expected...",
                //                     ),
                //                     SectionCount::new(
                //                         header.counts().qdcount(),
                //                         ancount,
                //                         0,
                //                         0,
                //                     ),
                //                 );
                //                 let mut res = <[u8; 12]>::from(out_header).to_vec();
                //                 res.extend(qsection_raw);
                //                 res.extend(res_asection.raw_domain);
                //                 if let Err(msg) = udp_socket.send_to(res.as_bytes(), _source) {
                //                     eprintln!("error sending message! {msg}")
                //                 }
                //             }
                //             None => {
                //                 eprintln!("Error parsing; missing qsection!");
                //             }
                //         }
                //     }
                //     Err(err) => {
                //         eprintln!("Error parsing; {err}");
                //     }
                // }
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
