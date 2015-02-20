#![crate_name = "aws"]
#![crate_type = "lib"]

#![feature(collections)]
#![feature(core)]
#![feature(os)]
#![feature(path)]
#![feature(std_misc)]

extern crate curl;
#[cfg(unix)] extern crate openssl;
extern crate "rustc-serialize" as serialize;
extern crate time;
extern crate url;
extern crate ini;

#[macro_use] extern crate log;

pub mod credentials;
pub mod client;
pub mod signers;
