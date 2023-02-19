# yk-verify
A fairly minimal yubikey verifier/authenticator.  

## Usage
Supply a slot containing an ECCP384 private key and paths containing the public keys connected to 
that private key you want to verify that the yubikey can provide a valid signature for.   
Ex:  
`yk-verify -s 9a -p ~/yk0_pub.pem,~/yk1_pub.pem`

If any connected yubikey is valid for any of the provided keys the binary exits with zero, otherwise it exits with 1.

## System requirements for running
System has `pcscd` running. On Linux distributions running systemd it can be started by `sudo systemctl start pcscd`.  

## Build local
1. Install Rust
2. Make sure libpcsclite exists on the machine
3. `cargo b -r -p yk-verify`

## Build a static binary
Use [the script provided for building musl](build-static.sh), it will build libpcsclite and then link to it statically.  

# License
This project is licensed under MPLv2, except for the included library (pcsc-lite), the license for that library
is provided [here](PCSC-LICENSE)
