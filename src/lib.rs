#![crate_name = "aws"]
#![crate_type = "lib"]

#![feature(collections)]
#![feature(convert)]

#[macro_use]
extern crate hyper;

#[cfg(unix)] extern crate openssl;
extern crate rustc_serialize as serialize;
extern crate time;
extern crate url;
extern crate ini;

#[macro_use]
extern crate log;
#[cfg(test)] extern crate env_logger;

pub mod credentials;
pub mod request;
pub mod signers;
