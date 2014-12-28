#![crate_name = "glacier"]
// #![desc = "A library to interact with AWS"]
// #![license = "MIT"]
#![crate_type = "lib"]

extern crate curl;
#[cfg(unix)] extern crate openssl;
extern crate serialize;

pub mod glacier;

#[cfg (test)]
mod test;
