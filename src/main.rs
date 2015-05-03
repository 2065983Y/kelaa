use std::env;
use std::process::exit;

fn main() {
  run_to_first_arg();
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


