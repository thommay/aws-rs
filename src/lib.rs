#![crate_name = "aws"]
#![crate_type = "lib"]
#![feature(macro_rules)]

extern crate curl;
#[cfg(unix)] extern crate openssl;
extern crate serialize;
extern crate time;
extern crate url;

pub mod signers;
pub mod request;
