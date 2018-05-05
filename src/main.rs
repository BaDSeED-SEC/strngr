extern crate base64;
extern crate byteorder;
extern crate capstone;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure_derive;
extern crate failure;
extern crate itertools;
extern crate min_max_heap;
extern crate noisy_float;
extern crate num_traits;
extern crate rida;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate tempfile;

mod analysis;
mod arch;
mod image;
mod loader;
mod util;

use clap::{Arg, App};

fn main() {
    let matches = App::new("strngr")
                      .version("0.1.0")
                      .author("Sam L. Thomas <m@kali.ai>")
                      .about(include_str!("../strngr.descr.in"))
                      .arg(Arg::with_name("ida")
                           .help("Use IDA Pro binary at specified path")
                           .long("ida")
                           .value_name("IDA")
                           .takes_value(true))
                      .arg(Arg::with_name("count")
                           .help("Number of functions to display (default: 100)")
                           .long("count")
                           .short("n")
                           .value_name("COUNT")
                           .takes_value(true))
                      .arg(Arg::with_name("FILE")
                           .help("Input file to analyse")
                           .required(true)
                           .index(1))
                      .get_matches();

    let ida_bin = matches.value_of("ida").unwrap_or("idal");
    let count = value_t!(matches, "count", usize).unwrap_or(100);
    let input = matches.value_of("FILE").unwrap();

    if let Err(e) = analysis::run(&ida_bin, &input, count) {
        println!("Error: {}", e.cause())
    }
}
