extern crate aws;

#[macro_use]
extern crate log;
extern crate env_logger;
use aws::request::ApiClient;
use aws::credentials::Credentials;

extern crate xml;
use xml::reader::EventReader;
use xml::reader::events::*;

pub fn main() {
    env_logger::init().unwrap();
    let cred = Credentials::new().load();
    let region = "eu-west-1";
    let service = "ec2";
    let version = "2015-04-15";

    let client = ApiClient::new(cred, version, region, service);
    let res = client.get("DescribeInstances");
    // let mut output = String::new();
    // res.unwrap().read_to_string(&mut output);
    let mut parser = EventReader::new(res.unwrap());
    let mut b_s = String::new();
    for e in parser.events() {
        match e {
            XmlEvent::StartElement { name, .. } => {
                b_s = format!("{} {}", b_s, name.local_name);
                // info!("Start - {}", name.local_name);
            }
            XmlEvent::EndElement { .. } => {
                println!("{}", b_s);
                b_s = String::new();
                // info!("End - {}", name);
            }
            XmlEvent::Characters(inf) => {
                b_s = format!("{}: {}", b_s, inf);
                // info!("{}", inf);
            }
            XmlEvent::Error(e) => {
                error!("XML Parsing Error: {}", e);
                break;
            }
            _ => {}
        }
    }
    // info!("{:?}", output)
}
