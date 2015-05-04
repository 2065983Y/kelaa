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
  let args: Vec<_> = env::args().collect();
  if args.is_empty() {
    println!("Please supply dns name to query as parameter");
    exit(5);
  }
  let name_to_query = &args[1];
  println!("Name to query: {}", name_to_query);
  let parts_to_query = name_to_query.split(".");

  let name_server_address = parse_ipv4_address(read_nameserver().unwrap());
  println!("Using name server : {}", name_server_address);

  let udp_socket = UdpSocket::bind("127.0.0.1:12345").unwrap();
  set_socket_timeout(&udp_socket);
  let mut query_vec: Vec<u8> = Vec::new();
  let msg_id_1 = 0x07;
  let msg_id_2 = 0x09;
  query_vec.push(msg_id_1); // message id 1
  query_vec.push(msg_id_2); // message id 2
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

  for p in parts_to_query {
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

  let mut response_buf = [0; 100];

  let bytes_written = udp_socket.send_to(&query_vec, (name_server_address, 53)).unwrap();
  println!("wrote: {}", bytes_written);
  match udp_socket.recv_from(&mut response_buf) {
    Ok((n, address)) => {
      let mut response_vec: Vec<u8> = Vec::new();
      for &x in response_buf.iter() {
        response_vec.push(x);
      }
      println!("Got {} bytes from {} ", n, address);
      process_response(response_vec, &msg_id_1, &msg_id_2);
      println!("\nDone.");
      n
    },
    Err(e) => {
      println!("Could not read answer: {}", e);
      -1
    }
  };
}

fn process_response(response: Vec<u8>, msg_id_1: &u8, msg_id_2: &u8) {
  let mut iter = response.iter();

  let received_msg_id_1 = iter.next().unwrap() as &u8;
  if (msg_id_1 != received_msg_id_1) {
    println!("Error: expected first byte of message id to be {} but was {}",
      msg_id_1, received_msg_id_1);
    exit(9);
  }
  let received_msg_id_2 = iter.next().unwrap() as &u8;
  if (msg_id_2 != received_msg_id_2) {
    println!("Error: expected second byte of message id to be {} but was {}",
      msg_id_2, received_msg_id_2);
    exit(9);
  }

  let third_byte = iter.next().unwrap() as &u8;
  println!("\tIs a response? {}", check_single_bit(third_byte, 0));
  println!("\tIs standard query? {}", !(check_single_bit(third_byte, 1) && check_single_bit(third_byte, 2) && check_single_bit(third_byte, 3)));

  let mut byte = None;
  while {
    byte = iter.next();
    byte != None
  } {
    print!("{} ", byte.unwrap() as &u8);
  }

  let mut byte_option = iter.next();
  /*for b in response {
    print!("{} ", b as u8);
  }
  */
  //println!("Got {}", response.len());
}

fn check_single_bit(b: &u8, position: u32) -> bool {
  let powered = (2 as u8).pow(position);
  powered == b & (1 << position)
}

fn read_nameserver() -> Option<String> {
  match File::open("/etc/resolv.conf") {
    Ok(file) => parse_resolv_conf(file),
    Err(e) => {
      println!("Could not read /etc/resolv.conf : {}", e);
      None
    }
  }
}

fn parse_resolv_conf(file: File) -> Option<String> {
  let mut s = String::new();
  let mut f = file;
  f.read_to_string(&mut s);
  let ns_lines = s.split("\n").filter(|&l| l.starts_with("nameserver"));
  let mut ns_addresses = ns_lines.flat_map(|l| l.split_whitespace().skip(1).next());
  return ns_addresses.next().map(|x| x.to_string());
}

fn parse_ipv4_address(src: String) -> Ipv4Addr {
  match Ipv4Addr::from_str(src.as_str()) {
    Ok(result) => result,
    Err(e) => exit(4)
  }
}

fn set_socket_timeout(socket: &UdpSocket) {
  socket.set_time_to_live(1);
  let raw_fd = socket.as_raw_fd();
  //setsockopt(raw_fd.as_sock_t(), SO_RCVTIMEO, 1000, 1000);
}

