fn main() {
    println!("cargo:rustc-link-search=/home/gramar/code/rust/yubi-rs/vendored/pcsc-lite-1.9.9/out/lib");
    println!("cargo:rustc-link-lib=static=pcsclite");
}