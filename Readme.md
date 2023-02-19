# yk-verify
A fairly minimal Yubikey verifier/authenticator.  

## Usage
Supply a slot containing an ECCP384 private key and paths containing the public keys connected to 
that private key you want to verify that the Yubikey can provide a valid signature for.   
Ex in:  
`yk-verify -s 9a -p ~/yk0_pub.pem,~/yk1_pub.pem`
Ex out:  
```bash
[me@machine yk-verify]$ ./target/x86_64-unknown-linux-musl/lto/yk-verify -s 9a -p ../linux-utils/pub0.pem 
Found card Yubico YubiKey OTP+FIDO+CCID 00 00
Found Pin policy "Always", please enter pin: 
Pin verified.
Generated 1024 byte message, starting signing operation.
Found touch policy "Cached", please touch the smartcard.
Verifying signature against public key at index 0
Signature verified.
```

If any connected Yubikey is valid for any of the provided keys the binary exits with zero, otherwise it exits with 1.  
If no keys can be found, or a `SharingViolation` occurs, that might be because `gpg` has locked the card. Kill the gpg agent or 
reinsert the card to fix it.  

## System requirements for running
System has `pcscd` running. On Linux distributions running systemd it can be started by `sudo systemctl start pcscd`.  

## Build for a local machine
1. Install Rust
2. Make sure libpcsclite exists on the machine
3. `cargo b -r -p yk-verify`

## Build a static binary
Use [the script provided for building musl](build-static.sh), it will build libpcsclite and then link to it statically.  

# License
This project is licensed under [MPLv2](LICENSE), except for the included library (pcsc-lite), the license for that library
is provided [here](PCSC-LICENSE)
