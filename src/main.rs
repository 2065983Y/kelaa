#![feature(convert)]

use std::env;
use std::process::exit;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;

fn main() {
  let args: Vec<_> = env::args().collect();
  if args.is_empty() {
    println!("Please supply dns name to query as parameter");
    exit(5);
  }
  let name_to_query = &args[1];
  println!("Name to query: {}", name_to_query);
  let name_server_address = parse_ipv4_address(read_nameserver().unwrap());
  println!("Using name server : {}", name_server_address);

  let udp_socket = UdpSocket::bind("127.0.0.1:12345").unwrap();
  let buf = &mut [0];
  let bytes_written = udp_socket.send_to(&[7], (name_server_address, 53)).unwrap();
  println!("wrote: {}", bytes_written);
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


