#![feature(convert)]
#![feature(udp)]
#![feature(custom_derive)]
#![feature(custom_derive, plugin)]
#![plugin(num_macros)]
//#![feature(core)]

//extern crate core;
extern crate num;

use std::env;
use std::process::exit;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, UdpSocket};
use std::str::FromStr;
use std::os::unix::io::AsRawFd;
use num::FromPrimitive;

fn main() {
  let name_to_query = read_name_to_query_from_command_line();
  println!("Name to query: {}", name_to_query);

  let name_server_address = parse_ipv4_address(read_nameserver());
  println!("Using name server : {}", name_server_address);

  let udp_socket = bind_client_socket();

  let msg_id = (0x07, 0x09);  // TODO randomise message id

  let query_vec = construct_a_record_query(name_to_query, msg_id);
  match udp_socket.send_to(&query_vec, (name_server_address, 53)) {
    Ok(bytes_written) => println!("Wrote {} bytes", bytes_written),
    Err(e) => {
      println!("Could not make query: {}", e);
      exit(19);
    }
  }

  let mut response_buf = [0; 100];
  let processed_bytes = match udp_socket.recv_from(&mut response_buf) {
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
  println!("Processed all {} bytes, exiting. Bye!.", processed_bytes);
}

fn process_response(response: Vec<u8>, msg_id: &(u8, u8)) {
  let mut iter = response.iter();

  assert_byte(&iter.next(), &msg_id.0, "first byte of message id");
  assert_byte(&iter.next(), &msg_id.1, "second byte of message id");

  process_next_byte(&iter.next(), |b| {
    println!("\tIs a response? {}", check_single_bit(b, 7));
    println!("\tIs standard query? {}", !(check_single_bit(b, 6) && check_single_bit(b, 5) && check_single_bit(b, 4) && check_single_bit(b, 3)));
    println!("\tAA? {}", check_single_bit(b, 2));
    println!("\tTC? {}", check_single_bit(b, 1));
    println!("\tRD? {}", check_single_bit(b, 0));
    b.clone()
  });

  process_next_byte(&iter.next(), |b| {
    println!("\tRA? {}", check_single_bit(b, 7));
    println!("\t<must be three zero bits> {}", !(check_single_bit(b, 6) && check_single_bit(b, 5) && check_single_bit(b, 4)));
    let rcode = b & 15;
    println!("\trcode: {}", rcode);

    let rcode_obj = FromPrimitive::from_u8(rcode);
    let rcode_unwrapped = rcode_obj.expect(format!("Could not parse {} as rcode", rcode).as_str());
    if !check_rcode(rcode_unwrapped) {
      exit(11);
    }
    b.clone()
  });

  println!("\tQDCOUNT: {}", get_two_byte_value(&iter.next(), &iter.next()));
  println!("\tANCOUNT: {}", get_two_byte_value(&iter.next(), &iter.next()));
  println!("\tNSCOUNT: {}", get_two_byte_value(&iter.next(), &iter.next()));
  println!("\tARCOUNT: {}", get_two_byte_value(&iter.next(), &iter.next()));

  let mut name_part_byte: u8;
  let mut name = String::new();
  while {
    name_part_byte = get_byte(&iter.next()) as u8;
    name_part_byte != 0
  } {
    let part_length = name_part_byte.clone();
    for _ in 0..part_length {
      name.push(get_byte(&iter.next()) as char);
    }
    name.push('.');
  }
  println!("\tQNAME: {}", name);

  println!("\tQTYPE: {}", print_type(get_two_byte_value(&iter.next(), &iter.next()) as u8));
  println!("\tQCLASS: {}", get_two_byte_value(&iter.next(), &iter.next()));

  let first_name_byte = get_byte(&iter.next()) as u8;
  let first_name_bit = check_single_bit(&first_name_byte, 7);
  let second_name_bit = check_single_bit(&first_name_byte, 6);
  let response_name_is_pointer = first_name_bit && second_name_bit;
  println!("\tIs pointer? {}", response_name_is_pointer);
  if response_name_is_pointer {
    iter.next();
  }

  println!("\tTYPE: {}", print_type(get_two_byte_value(&iter.next(), &iter.next()) as u8));
  println!("\tCLASS: {}", get_two_byte_value(&iter.next(), &iter.next()));

  let ttl_byte_1 = get_byte(&iter.next()) as u32;
  let ttl_byte_2 = get_byte(&iter.next()) as u32;
  let ttl_byte_3 = get_byte(&iter.next()) as u32;
  let ttl_byte_4 = get_byte(&iter.next()) as u32;
  let ttl = (ttl_byte_1 << 24) + (ttl_byte_2 << 16) + (ttl_byte_3 << 8) + (ttl_byte_4 << 0);
  println!("\tttl: {} {} {} {} {}", ttl_byte_1, ttl_byte_2, ttl_byte_3, ttl_byte_4, ttl);

  let rdlength = get_two_byte_value(&iter.next(), &iter.next());
  println!("\trdlength: {}", rdlength);

  print!("\tRESPONSE: ");
  for _ in 0..rdlength {
    print!("{}.", get_byte(&iter.next()) as u8);
  }
}

fn process_next_byte<F>(byte_option: &Option<&u8>, processor: F) -> u8
  where F: Fn(&u8) -> u8 {
    let b = byte_option.expect("Iterator is empty!");
    processor(b)
}

fn assert_byte(byte_option: &Option<&u8>, expected: &u8, msg: &str) {
    process_next_byte(byte_option, |b| {
      if expected != b {
        println!("Error: expected {} to be {} but was {}",
          msg, expected, b);
        exit(9);
      }
      b.clone()
    });
}

fn get_byte(byte_option: &Option<&u8>) -> u8 {
  process_next_byte(byte_option, |b| {
    b.clone()
  })
}

fn get_two_byte_value(byte1: &Option<&u8>, byte2: &Option<&u8>) -> u32 {
  256 * get_byte(byte1) as u32 + get_byte(byte2) as u32
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

fn check_rcode(rcode: Rcode) -> bool {
  match rcode {
    Rcode::ROk => true,
    _ => {
        println!("\trcode: {:?}", rcode);
        false
    }
  }
}

fn print_type(type_code: u8) -> String {
  let record_type: RecordType = FromPrimitive::from_u8(type_code).
    expect(format!("Unknown type '{}'", type_code).as_str());
  format!("{:?}", record_type)
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
  match f.read_to_string(&mut s) {
    Ok(n) => println!("Read {} bytes from file.", n),
    Err(e) => {
      println!("Could not read data from file : {}", e);
      exit(6);
    }
  }

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
  let client_local_port = "127.0.0.1:65530"; // TODO randomise and retry
  let udp_socket = UdpSocket::bind(client_local_port).ok().
    expect(format!("Could not bind UDP socket to {}", client_local_port).as_str());
  println!("Bound client UDP socket {}", client_local_port);
  set_socket_timeout(&udp_socket);
  udp_socket
}

// TODO implement :)
fn set_socket_timeout(socket: &UdpSocket) {
  let _ = socket.set_time_to_live(1);
  let _ /* raw_fd */  = socket.as_raw_fd();
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

#[derive(Debug, PartialEq, NumFromPrimitive)]
enum Rcode {
  ROk = 0,
  FormatError = 1,
  ServerFailure = 2,
  NameError = 3,
  NotImplemented = 4,
  Refused = 5
}

#[derive(Debug, PartialEq, NumFromPrimitive)]
enum RecordType {
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA = 6,
  WKS = 11,
  PTR = 12,
  MX = 15,
  SRV = 33,
  A6 = 38
}
