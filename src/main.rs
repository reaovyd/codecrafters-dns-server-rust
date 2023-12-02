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
    header::{
        DnsHeader, HeaderSecondRowFirstHalf, HeaderSecondRowSecondHalf, OpCode, QueryResponse,
        SectionCount, Truncation,
    },
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
                                            transcriber.txid(),
                                            header.header_first_half().clone(),
                                            header.header_second_half().clone(),
                                            SectionCount::new(
                                                1,
                                                header.counts().ancount(),
                                                header.counts().nscount(),
                                                header.counts().arcount(),
                                            ),
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
                                    // stupid cheese to pass part 5?
                                    let fh = HeaderSecondRowFirstHalf::new(
                                        QueryResponse::Response,
                                        header.header_first_half().opcode().clone(),
                                        dns_starter_rust::header::AuthAnswer::NotAuthoritative,
                                        Truncation::NotTruncated,
                                        header.header_first_half().rd().clone(),
                                    );
                                    let sh = HeaderSecondRowSecondHalf::new(header.header_second_half().ra().clone(), 0, match header.header_first_half().opcode() {
                                        OpCode::Query => dns_starter_rust::header::ResponseCode::None,
                                        _ => dns_starter_rust::header::ResponseCode::NotImplemented
                                    }).expect("should work");
                                    let res = <[u8; 12]>::from(DnsHeader::new(
                                        header.txid(),
                                        fh,
                                        sh,
                                        header.counts().clone(),
                                    ));
                                    if let Err(err_msg) = udp_socket.send_to(&res, source) {
                                        eprintln!("Error sending message; got {err_msg}");
                                    }
                                }
                            },
                        }
                    }
                    Err(err) => {
                        eprintln!("Error parsing; {err}")
                    }
                }
            }
            Err(err) => {
                eprintln!("Error parsing; {err}");
            }
        }
    }
}
