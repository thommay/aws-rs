#![crate_name = "aws"]
#![crate_type = "lib"]

// extern crate curl;
#[cfg(unix)] extern crate openssl;
extern crate "rustc-serialize" as serialize;
extern crate time;
extern crate url;
extern crate ini;

#[macro_use] extern crate log;

pub mod credentials;
pub mod request;
pub mod signers;
