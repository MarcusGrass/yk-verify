#![warn(clippy::pedantic)]
#![deny(unsafe_code)]

use yubi_lib::verify_signature;

fn main() {
    run_from_args(std::env::args());
}

fn run_from_args<It>(mut args: It)
where
    It: Iterator<Item = String>,
{
    let mut paths = Vec::with_capacity(4);
    let mut parsing_path = false;
    let mut slot = None;
    let mut parsing_slot = false;
    // Pop binary name first arg
    args.next();
    for arg in args {
        if parsing_path {
            for path in arg.split(',') {
                match std::fs::read_to_string(path) {
                    Ok(pem) => {
                        paths.push(pem);
                    }
                    Err(e) => {
                        eprintln!("Failed to read pem at {path}, will try to continue. Error {e}");
                    }
                }
            }
            parsing_path = false;
            continue;
        }
        if parsing_slot {
            match u8::from_str_radix(&arg, 16) {
                Ok(parsed) => {
                    slot = Some(parsed);
                }
                Err(e) => {
                    eprintln!("Failed to parse slot as a hex byte. Error {e}");
                }
            }
            parsing_slot = false;
            continue;
        }
        match arg.as_str() {
            "-p" | "--paths" => parsing_path = true,
            "-s" | "--slot" => parsing_slot = true,
            _ => {
                print_help();
                return;
            }
        }
    }
    let success = match (!paths.is_empty(), slot) {
        (true, Some(slot)) => match verify_signature(&paths, slot) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("Failed to verify signature, error: {e}");
                false
            }
        },
        (false, Some(_)) => {
            eprintln!("No paths provided, no signatures to verify.");
            false
        }
        (true, None) => {
            eprintln!("No slot provided, can't verify signature.");
            false
        }
        (false, None) => {
            eprintln!("No paths or slot provided, can't verify signature.");
            false
        }
    };
    if !success {
        std::process::exit(-1);
    }
}

fn print_help() {
    println!(
        "Usage: yk-verify [OPTION]...\n\
                Authenticate a Yubikey using a PIV ECP384 key.\n\
                \
                -h, --help\t\tDisplay this message\n\
                -p, --paths\t\tFile paths for yubikey public keys (comma separated, PEM format).\n\
                -s, --slot\t\tHex-string slot number on the card where the private key is stored, ex: 9a\n\
                Generates a random message and requests a Yubikey to sign it with an ECP384 key at the provided slot \n\
                and tries to verify that signature against any of the provided public keys.");
}
