use time::now_utc;
use std::ascii::AsciiExt;
use openssl::crypto::hash::Hasher;
use openssl::crypto::hash::HashType::SHA256;
use serialize::hex::ToHex;
use request::Header;

pub struct SigV4 {
    headers: Vec<Header>,
    path: Option<String>,
    method: Option<String>,
    query: Option<String>,
    payload: Option<String>,
    date: String,
}

impl SigV4 {
    pub fn new() -> SigV4{
        let dt = now_utc();
        SigV4 {
            headers: Vec::new(),
            path: None,
            method: None,
            query: None,
            payload: None,
            date: dt.rfc3339().to_string(),
        }
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

    fn hashed_payload(self) -> String {
        let val = match self.payload {
            Some(x) => x,
            None => "".to_string(),
        };
        let mut h = Hasher::new(SHA256);
        h.update(val.as_bytes());
        h.finalize().as_slice().to_hex().to_string()
    }

    fn signed_headers(mut self) -> String {
        self.sort_headers();
        let mut h = String::new();

        for header in self.headers.iter() {
            let key = header.key.to_ascii_lower();
            if key == "authorization" {
                continue;
            }
            h.push_str(key.as_slice());
            h.push(';')
        }
        h.trim_right_chars(';').to_string()
    }

    fn canonical_headers(mut self) -> String {
        self.sort_headers();
        let mut h = String::new();

        for header in self.headers.iter() {
            let key = header.key.to_ascii_lower();
            if key == "authorization" {
                continue;
            }
            h.push_str(format!("{}:{}\n", key, canonical_value(&header.value)).as_slice());
        }
        h
    }

    fn sort_headers(&mut self) {
        self.headers.sort_by(|a,b|
                        a.key.to_ascii_lower().cmp(&b.key.to_ascii_lower()))
    }
}

fn canonical_value(val: &String) -> String {
    if val.starts_with("\""){
        val.to_string()
    } else {
        val.replace("  ", " ").trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::SigV4;
    use request::Header;

    #[test]
    fn test_new_sigv4() {
        let sig = SigV4::new();
        assert_eq!(sig.headers.len(), 0)
    }

    #[test]
    fn test_add_header() {
        let h = Header{ key: "test".to_string(),
        value: "a string".to_string()};

        let sig = SigV4::new().header(h);
        assert_eq!(sig.headers[0].value.as_slice(), "a string")
    }

    #[test]
    fn test_signature() {
        let sig = SigV4::new().method("GET".to_string()).path("/".to_string());
        assert_eq!(sig.signature().as_slice(), "GET")
    }

    #[test]
    fn test_signed_headers() {
        let h = Header{ key: "test".to_string(),
        value: "a string".to_string()};
        let h2 = Header{ key: "Content-Type".to_string(),
        value: "application/x-www-form-urlencoded; charset=utf-8".to_string()};
        let h3 = Header{ key: "X-Amz-Date".to_string(),
        value: "20120228T030031Z".to_string()};
        let h4 = Header{ key: "Authorization".to_string(),
        value: "none".to_string()};

        let sig = SigV4::new().header(h).header(h2).header(h3).header(h4);
        assert_eq!(sig.signed_headers().as_slice(), "content-type;test;x-amz-date")
    }

    #[test]
    fn test_hashed_payload() {
        let sig = SigV4::new().
            payload("Action=ListUsers&Version=2010-05-08".to_string());
        assert_eq!(sig.hashed_payload(),
        "b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2")
    }

    #[test]
    fn test_empty_payload() {
        let sig = SigV4::new();
        assert_eq!(sig.hashed_payload(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    #[test]
    fn test_canonical_headers() {
        let h = Header{ key: "Xyz".to_string(), value: "1".to_string() };
        let h2 = Header{ key: "Abc".to_string(), value: "2".to_string() };
        let h3 = Header{ key: "Mno".to_string(), value: "3".to_string() };
        let h4 = Header{ key: "Authorization".to_string(), value: "4".to_string() };
        let sig = SigV4::new().header(h).header(h2).header(h3).header(h4);
        assert_eq!(sig.canonical_headers().as_slice(), "abc:2\nmno:3\nxyz:1\n")
    }

    #[test]
    fn test_prune_whitespace() {
        let h = Header{ key: "Abc".to_string(), value: "a  b  c".to_string() };
        let sig = SigV4::new().header(h);
        assert_eq!(sig.canonical_headers().as_slice(), "abc:a b c\n")
    }

    #[test]
    fn test_no_prune_quoted() {
        let h = Header{ key: "Abc".to_string(), value: "\"a  b  c\"".to_string() };
        let sig = SigV4::new().header(h);
        assert_eq!(sig.canonical_headers().as_slice(), "abc:\"a  b  c\"\n")
    }

    #[test]
    fn test_should_be_3339() {
        let sig = SigV4::new();
        assert!(sig.date.ends_with("Z"))
    }
}
