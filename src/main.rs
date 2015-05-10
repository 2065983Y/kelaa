#![feature(convert)]
#![feature(udp)]
//#![feature(core)]

//extern crate core;

use std::env;
use std::process::exit;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, UdpSocket};
use std::str::FromStr;
use std::os::unix::io::AsRawFd;
//use std::net::setsockopt;
//use core::array::FixedSizeArray;

fn main() {
  let name_to_query = read_name_to_query_from_command_line();
  println!("Name to query: {}", name_to_query);

  let name_server_address = parse_ipv4_address(read_nameserver());
  println!("Using name server : {}", name_server_address);

  let udp_socket = bind_client_socket();

  let msg_id = (0x07, 0x09);  // TODO randomise message id
  let query_vec = construct_a_record_query(name_to_query, msg_id);

  let mut response_buf = [0; 100];

  match udp_socket.send_to(&query_vec, (name_server_address, 53)) {
    Ok(bytes_written) => println!("Wrote {} bytes", bytes_written),
    Err(e) => {
      println!("Could not make query: {}", e);
      exit(19);
    }
  }

  match udp_socket.recv_from(&mut response_buf) {
    Ok((n, address)) => {
      let mut response_vec: Vec<u8> = Vec::new();
      for &x in response_buf.iter() {
        response_vec.push(x);
      }
      println!("Got {} bytes from {} ", n, address);
      process_response(response_vec, &msg_id);
      println!("\nDone.");
      n
    },
    Err(e) => {
      println!("Could not read answer: {}", e);
      -1
    }
  };
}

fn process_response(response: Vec<u8>, msg_id: &(u8, u8)) {
  let mut iter = response.iter();

  let received_msg_id_1 = iter.next().unwrap() as &u8;
  if (&msg_id.0 != received_msg_id_1) {
    println!("Error: expected first byte of message id to be {} but was {}",
      msg_id.0, received_msg_id_1);
    exit(9);
  }
  let received_msg_id_2 = iter.next().unwrap() as &u8;
  if (&msg_id.1 != received_msg_id_2) {
    println!("Error: expected second byte of message id to be {} but was {}",
      msg_id.1, received_msg_id_2);
    exit(9);
  }

  let third_byte = iter.next().unwrap() as &u8;
  println!("\tIs a response? {}", check_single_bit(third_byte, 7));
  println!("\tIs standard query? {}", !(check_single_bit(third_byte, 6) && check_single_bit(third_byte, 5) && check_single_bit(third_byte, 4) && check_single_bit(third_byte, 3)));
  println!("\tAA? {}", check_single_bit(third_byte, 2));
  println!("\tTC? {}", check_single_bit(third_byte, 1));
  println!("\tRD? {}", check_single_bit(third_byte, 0));

  let fourth_byte = iter.next().unwrap() as &u8;
  println!("\tRA? {}", check_single_bit(fourth_byte, 7));
  println!("\t<must be three zero bits> {}", !(check_single_bit(fourth_byte, 6) && check_single_bit(fourth_byte, 5) && check_single_bit(fourth_byte, 4)));
  let rcode = fourth_byte & 15;
  println!("\trcode: {}", rcode);
  if !check_rcode(rcode) {
    exit(11);
  }

  let fifth_byte = iter.next().unwrap().clone() as u32;
  let sixth_byte = iter.next().unwrap().clone() as u32;
  println!("\tQDCOUNT: {}", 256 * fifth_byte + sixth_byte);

  let seventh_byte = iter.next().unwrap().clone() as u32;
  let eighth_byte = iter.next().unwrap().clone() as u32;
  println!("\tANCOUNT: {}", 256 * seventh_byte + eighth_byte);

  let ninth_byte = iter.next().unwrap().clone() as u32;
  let tenth_byte = iter.next().unwrap().clone() as u32;
  println!("\tNSCOUNT: {}", 256 * ninth_byte + tenth_byte);

  let eleventh_byte = iter.next().unwrap().clone() as u32;
  let twelwth_byte = iter.next().unwrap().clone() as u32;
  println!("\tARCOUNT: {}", 256 * eleventh_byte + twelwth_byte);

  let mut name_part_byte: &u8;
  let mut name = String::new();
  while {
    name_part_byte = iter.next().unwrap() as &u8;
    name_part_byte != &(0u8)
  } {
    let part_length = name_part_byte.clone();
    for i in 0..part_length {
      name.push(iter.next().unwrap().clone() as char);
    }
    name.push('.');
  }
  println!("\tQNAME: {}", name);

  let q_type_byte_1 = iter.next().unwrap() as &u8;
  let q_type_byte_2 = iter.next().unwrap() as &u8;
  println!("\tQTYPE: {}", print_type(256 * q_type_byte_1 + q_type_byte_2));

  let q_class_byte_1 = iter.next().unwrap() as &u8;
  let q_class_byte_2 = iter.next().unwrap() as &u8;
  println!("\tQCLASS: {}", 256 * q_class_byte_1 + q_class_byte_2);

  let first_name_byte = iter.next().unwrap() as &u8;
  let first_name_bit = check_single_bit(first_name_byte, 7);
  let second_name_bit = check_single_bit(first_name_byte, 6);
  let response_name_is_pointer = first_name_bit && second_name_bit;
  println!("\tIs pointer? {}", response_name_is_pointer);
  if (response_name_is_pointer) {
    iter.next();
  }

  let type_byte_1 = iter.next().unwrap() as &u8;
  let type_byte_2 = iter.next().unwrap() as &u8;
  println!("\tTYPE: {}", print_type(256 * type_byte_1 + type_byte_2));

  let class_byte_1 = iter.next().unwrap() as &u8;
  let class_byte_2 = iter.next().unwrap() as &u8;
  println!("\tCLASS: {}", 256 * class_byte_1 + class_byte_2);

  let ttl_byte_1 = iter.next().unwrap().clone() as u32;
  let ttl_byte_2 = iter.next().unwrap().clone() as u32;
  let ttl_byte_3 = iter.next().unwrap().clone() as u32;
  let ttl_byte_4 = iter.next().unwrap().clone() as u32;
  let ttl = (ttl_byte_1 << 24) + (ttl_byte_2 << 16) + (ttl_byte_3 << 8) + (ttl_byte_4 << 0);
  println!("\tttl: {} {} {} {} {}", ttl_byte_1, ttl_byte_2, ttl_byte_3, ttl_byte_4, ttl);

  let rdlength_byte_1 = iter.next().unwrap() as &u8;
  let rdlength_byte_2 = iter.next().unwrap() as &u8;
  let rdlength = rdlength_byte_1 * 256 + rdlength_byte_2;
  println!("\trdlength: {}", rdlength);

  print!("\tRESPONSE: ");
  for i in 0..rdlength {
    print!("{}.", iter.next().unwrap() as &u8);
  }
/*
  let mut byte = None;
  while {
    byte = iter.next();
    byte != None
  } {
    print!("{} ", byte.unwrap() as &u8);
  }
*/
}

fn construct_a_record_query(name_to_query: String, msg_id: (u8, u8)) -> Vec<u8> {
    let mut query_vec: Vec<u8> = Vec::new();
    query_vec.push(msg_id.0); // message id 1
    query_vec.push(msg_id.1); // message id 2
    query_vec.push(0x01); // qr, opcode, aa, tc, rd
    query_vec.push(0x00); // ra, res1, res2, res3, rcode
    query_vec.push(0x00); // qdcount 1
    query_vec.push(0x01); // qdcount 2
    query_vec.push(0x00); // ancount 1
    query_vec.push(0x00); // ancount 2
    query_vec.push(0x00); // nscount 1
    query_vec.push(0x00); // nscount 2
    query_vec.push(0x00); // arcount 1
    query_vec.push(0x00); // arcount 2

    for p in name_to_query.split(".") {
      query_vec.push(p.as_bytes().len() as u8); // length
      for &c in p.as_bytes() {
        query_vec.push(c as u8); // query
      }
    }
    query_vec.push(0x00); // end name

    query_vec.push(0x00); // qtype 1
    query_vec.push(0x01); // qtype 2
    query_vec.push(0x00); // qclass 1
    query_vec.push(0x01); // qclass 2
    query_vec
}

fn check_rcode(rcode: u8) -> bool {
  if rcode != 0 {
    if rcode == 1 {
      println!("\trcode : Format error.");
    }
    if rcode == 2 {
      println!("\trcode : Server failure.");
    }
    if rcode == 3 {
      println!("\trcode : Name error.");
    }
    if rcode == 4 {
      println!("\trcode : Not implemented.");
    }
    if rcode == 5 {
      println!("\trcode : Refused.");
    }
    return false;
  }
  true
}

fn print_type(type_code: u8) -> String {
  if type_code == 1 { return "A".to_string(); }
  if type_code == 2 { return "NS".to_string(); }
  if type_code == 5 { return "CNAME".to_string(); }
  if type_code == 6 { return "SOA".to_string(); }
  if type_code == 11 { return "WKS".to_string(); }
  if type_code == 12 { return "PTR".to_string(); }
  if type_code == 15 { return "MX".to_string(); }
  if type_code == 33 { return "SRV".to_string(); }
  if type_code == 38 { return "A6".to_string(); }
  return format!("Unknown type {}", type_code);
}

fn check_single_bit(b: &u8, position: u32) -> bool {
  let powered = (2 as u8).pow(position);
  powered == b & (1 << position)
}

fn read_nameserver() -> String {
  match File::open("/etc/resolv.conf") {
    Ok(file) => parse_resolv_conf(file),
    Err(e) => {
      println!("Could not read /etc/resolv.conf : {}", e);
      exit(6);
    }
  }
}

fn parse_resolv_conf(file: File) -> String {
  let mut s = String::new();
  let mut f = file;
  f.read_to_string(&mut s);
  let ns_lines = s.split("\n").filter(|&l| l.starts_with("nameserver"));
  let mut ns_addresses = ns_lines.flat_map(|l| l.split_whitespace().skip(1).next());
  return ns_addresses.next().map(|x| x.to_string()).
    expect((format!("Could find read name server from {}", s).as_str()));
}

fn parse_ipv4_address(src: String) -> Ipv4Addr {
  Ipv4Addr::from_str(src.as_str()).ok().expect(
      format!("Could not parse ipv4 address from '{}', e", src).as_str())
}

fn bind_client_socket() -> UdpSocket {
  let client_local_port = "127.0.0.1:65530"; // todo randomise and retry
  let udp_socket = (UdpSocket::bind(client_local_port).ok().
    expect(format!("Could not bind UDP socket to {}", client_local_port).as_str()));
  println!("Bound client UDP socket {}", client_local_port);
  set_socket_timeout(&udp_socket);
  udp_socket
}

// TODO implement :)
fn set_socket_timeout(socket: &UdpSocket) {
  socket.set_time_to_live(1);
  let raw_fd = socket.as_raw_fd();
  //setsockopt(raw_fd.as_sock_t(), SO_RCVTIMEO, 1000, 1000);
}

fn read_name_to_query_from_command_line() -> String {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
      println!("Please supply DNS name to query as parameter. Exiting.");
      exit(5);
    }
    args[1].clone()
}
