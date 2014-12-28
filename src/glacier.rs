use std::ascii::AsciiExt;
use openssl::crypto::hash::Hasher;
use openssl::crypto::hash::HashType::SHA256;
use serialize::hex::ToHex;

pub struct Header {
    pub key: String,
    pub value: String,
}

pub struct SigV4 {
    headers: Vec<Header>,
    path: Option<String>,
    method: Option<String>,
    query: Option<String>,
    payload: Option<String>,
}

impl SigV4 {
    pub fn new() -> SigV4{
        SigV4 {
            headers: Vec::new(),
            path: None,
            method: None,
            query: None,
            payload: None,
        }
    }

    pub fn headers(self) -> Vec<Header> {
        self.headers
    }

    pub fn header(mut self, header: Header) -> SigV4 {
        self.headers.push(header);
        self
    }

    pub fn path(mut self, path: String) -> SigV4 {
        self.path = Some(path);
        self
    }

    pub fn method(mut self, method: String) -> SigV4 {
        self.method = Some(method);
        self
    }

    pub fn query(mut self, query: String) -> SigV4 {
        self.query = Some(query);
        self
    }

    pub fn payload(mut self, payload: String) -> SigV4 {
        self.payload = Some(payload);
        self
    }

    pub fn signature(self) -> String {
        self.method.unwrap()
    }

    pub fn hashed_payload(self) -> String {
        let val = match self.payload {
            Some(x) => x,
            None => "".to_string(),
        };
        let mut h = Hasher::new(SHA256);
        h.update(val.as_bytes());
        h.finalize().as_slice().to_hex().to_string()
    }

    pub fn signed_headers(mut self) -> String {
        let mut signed = String::new();
        self.sorted_headers();

        for header in self.headers().iter() {
            let key = header.key.to_ascii_lower();
            if key == "authorization" {
                continue;
            }
            signed.push_str(key.as_slice());
            signed.push(';')
        }
        signed.trim_right_chars(';').to_string()
    }

    fn sorted_headers(&mut self) {
        self.headers.sort_by(|a,b|
                        a.key.to_ascii_lower().cmp(&b.key.to_ascii_lower()))
    }
}
