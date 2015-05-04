#![feature(convert)]
#![feature(udp)]

//extern crate core;

use std::env;
use std::process::exit;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
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
/*  println!("Parts to query: ");
  for p in parts_to_query {
    print!("{} {} / ", p, p.len());
  }
*/
  println!("");

  let name_server_address = parse_ipv4_address(read_nameserver().unwrap());
  println!("Using name server : {}", name_server_address);

  let mut udp_socket = UdpSocket::bind("127.0.0.1:12345").unwrap();
  set_socket_timeout(&udp_socket);
  //let mut buf = [0u8, ..1000];
  let mut query_vec: Vec<u8> = Vec::new();
//[ 9, 9, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x96 ]; 
  query_vec.push(0x07); // message id 1
  query_vec.push(0x09); // message id 2
  query_vec.push(0x00); // qr, opcode, aa, tc, rd, ra
  query_vec.push(0x00); // res1, res2, res3, rcode
  query_vec.push(0x00); // qdcount 1
  query_vec.push(0x01); // qdcount 2
  query_vec.push(0x00); // ancount 1
  query_vec.push(0x00); // ancount 2
  query_vec.push(0x00); // nscount 1
  query_vec.push(0x00); // nscount 2
  query_vec.push(0x00); // arcount 1
  query_vec.push(0x00); // arcount 2
  //query_vec.push(name_to_query.len() as u8); // number of bytes
  //println!("len vs given , {}, {}", name_to_query.len() as u8, 0x0a);
  //query_vec.push(0x0a); // number of bytes
/*  for c in name_to_query.clone().into_bytes() {
    query_vec.push(c as u8);
  A
*/
  for p in parts_to_query {
    query_vec.push(p.as_bytes().len() as u8); // length
    for &c in p.as_bytes() {
      query_vec.push(c as u8); // query
    }
  }
  /*query_vec.push(0x02); // lnegth
  query_vec.push('t' as u8); //query
  query_vec.push('i' as u8); //query
  query_vec.push(0x02); // lnegth
  query_vec.push('f' as u8); //query
  query_vec.push('i' as u8); //query
  */
  query_vec.push(0x00); // end name
  query_vec.push(0x00); // qtype 1
  query_vec.push(0x01); // qtype 2
  query_vec.push(0x00); // qclass 1
  query_vec.push(0x01); // qclass 2

  let mut response_buf = [0; 100];

/*
  let transaction_id: u32 = rand::random();
  let mut req_data_buf = [0u8, ..16];
  let mut req_data = BufWriter::new(req_data_buf);
  req_data.write_be_u64(0x41727101980).unwrap(); // connection_id, identifies the protocol.
  req_data.write_be_u32(0).unwrap(); // action: connect
  req_data.write_be_u32(transaction_id).unwrap();
  
  println!("{}", socket.send_to(req_data_buf, ("31.172.63.252", 80)));
*/

  let bytes_written = udp_socket.send_to(&query_vec, (name_server_address, 53)).unwrap();
  println!("wrote: {}", bytes_written);
  match udp_socket.recv_from(&mut response_buf) {
    Ok((n, address)) => {
      let mut response_vec: Vec<u8> = Vec::new();
      for &x in response_buf.iter() {
        response_vec.push(x);
      }
      //response_vec.push_all(&buf);
      println!("Got {} bytes:", n);
      for b in response_vec {
        print!("{} ", b as u8);
      }
      println!("\nDone.");
      n
    },
    Err(e) => {
      println!("Could not read answer: {}", e);
      -1
    }
  };
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


fn run_to_first_arg() {
  let args: Vec<_> = env::args().collect();
  if args.is_empty() {
    println!("Please supply command line parameter.");
    exit(2);
  }

  let m = args[1].parse::<u32>();
  match m {
    Ok(maximum) => run_to(maximum),
    Err(e)=> {
      println!("Could not parse int from {} : {}", args[1], e);
      exit(3); 
    }
  } 
 
  println!("The first argument is {}", args[1]);
}

fn run_to(m: u32) {
  for x in 0..m {
    println!("{}", x);
  }
}


