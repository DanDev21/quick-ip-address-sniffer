use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::process;
use std::sync::mpsc::{Sender, channel};
use std::thread;
use std::time::Duration;

const THREADS_NO: u16 = 1024;
const MAX_SUPPORTED_THREADS_NO: u16 = 1024;

const MAX_PORT_NO: u16 = 65535;

const TCP_CONNECTION_TRIAL_TIMEOUT_SECS: u8 = 1;

struct IpSnifferArguments {
    threads_no: u16,
    ip_addr: IpAddr,
}

impl IpSnifferArguments {

    fn new(environment_args: &[String]) -> Result<IpSnifferArguments, &'static str> {
        if 2 > environment_args.len() {
            return Err("you need at least to specify the ip address");
        } else if 4 < environment_args.len(){
            return Err("too many arguments");
        }

        // case: only the ip address
        let serialized_ip_addr: String = environment_args[1].clone();
        if let Ok(ip_addr) = IpAddr::from_str(&serialized_ip_addr) {
            return Ok(IpSnifferArguments { threads_no: THREADS_NO, ip_addr });
        }

        // case: only the help flag
        let flags: String = environment_args[1].clone();
        if 2 == environment_args.len() && (flags.contains("-h") || flags.contains("--help")) {
            println!("Ip sniffer usage manual:\
            \n\t-h OR --help -> will show you this helpful message\
            \n\t-t OR --threads-no -> will let you select how many threads will be used\
            \n");

            return Err("help");
        }

        // case: threads number flag & ip address
        if flags.contains("-t") || flags.contains("--threads") {
            let ip_addr = match IpAddr::from_str(&environment_args[3]) {
                Ok(ip_addr) => ip_addr,
                Err(_) => return Err("invalid ip address, it must be an IPv4 or IPv6")
            };

            let threads_no = match environment_args[2].parse::<u16>() {
                Ok(threads_no) => threads_no,
                Err(_) => return Err("invalid threads' number")
            };

            if MAX_SUPPORTED_THREADS_NO < threads_no {
                return Err("invalid threads' number (too big)")
            }

            return Ok(IpSnifferArguments { threads_no, ip_addr });
        }

        // case: invalid syntax
        return Err("invalid syntax")
    }
}

// helper function to save the main from the boiler plate code
fn get_ip_sniffer_args_from_environment() -> IpSnifferArguments {
    let environment_args: Vec<String> = env::args().collect();
    IpSnifferArguments::new(&environment_args).unwrap_or_else(
        |error: &str| {
            if error.eq("help") {
                process::exit(0);
            } else {
                eprintln!("{} problem parsing the arguments: {}", environment_args[0], error);
                process::exit(0);
            }
        }
    )
}

fn scan_ip_addr(ip_addr: IpAddr, sender: Sender<u16>, starting_port: u16, threads_no: u16) {
    let mut port: u16 = starting_port + 1;
    loop {
        if let Ok(sock_addr) = SocketAddr::try_from((ip_addr, port)) {
            match TcpStream::connect_timeout(
                &sock_addr,
                Duration::from_secs(TCP_CONNECTION_TRIAL_TIMEOUT_SECS as u64)
            ) {
                Ok(_) => {
                    print!(".");

                    io::stdout().flush().unwrap();
                    sender.send(port).unwrap();
                }
                Err(_) => {}
            }
        }

        if threads_no >= MAX_PORT_NO - port {
            break;
        }

        port += threads_no;
    }
}

fn main() {
    let ip_sniffer_args: IpSnifferArguments = get_ip_sniffer_args_from_environment();
    let (sender, receiver) = channel();

    let ip_addr = ip_sniffer_args.ip_addr;
    let threads_no = ip_sniffer_args.threads_no;
    for i in 0..ip_sniffer_args.threads_no {
        // cloning the transmitter, so each thread will have its owned transmitter
        let transmitter_clone = sender.clone();

        thread::spawn(move || {
            scan_ip_addr(ip_addr, transmitter_clone, i, threads_no);
        });
    }

    drop(sender);

    let mut results: Vec<u16> = vec![];
    for result in receiver {
        results.push(result);
    }
    results.sort();

    println!();
    for result in results {
        println!("{} is opened", result);
    }
}