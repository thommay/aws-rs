use time::now_utc;
use time::Tm;
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
    date: Tm,
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
            date: dt,
        }
    }

    pub fn header(mut self, header: Header) -> SigV4 {
        self.headers.push(header);
        self
    }

    pub fn date(mut self) -> SigV4 {
        self.headers.push((Header{ key: "X-Amz-Date".to_string(), value: self.date.strftime("%Y%m%dT%H%M%SZ").unwrap().to_string()}));
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
        self.hashed_canonical_request()
    }

    fn hashed_canonical_request(self) -> String {
        let mut h = Hasher::new(SHA256);
        h.update(self.canonical_request().as_bytes());
        h.finalize().as_slice().to_hex().to_string()
    }

    fn hashed_payload(&self) -> String {
        let val = match self.payload {
            Some(ref x) => x.to_string(),
            None => "".to_string(),
        };
        let mut h = Hasher::new(SHA256);
        h.update(val.as_bytes());
        h.finalize().as_slice().to_hex().to_string()
    }

    fn signed_headers(&mut self) -> String {
        self.headers.sort_by(|a,b| a.key.to_ascii_lower().cmp(&b.key.to_ascii_lower()));
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

    fn canonical_headers(&mut self) -> String {
        self.headers.sort_by(|a,b| a.key.to_ascii_lower().cmp(&b.key.to_ascii_lower()));
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

    fn canonical_request(mut self) -> String {
        format!("{}\n{}\n{}\n{}\n{}\n{}", expand_string(&self.method),
                expand_string(&self.path),
                expand_string(&self.query),
                self.canonical_headers(),
                self.signed_headers(),
                self.hashed_payload()
        )
    }

}

fn expand_string(val: &Option<String>) -> String {
    match *val {
        None => "".to_string(),
        Some(ref x) => x.to_string(),
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
    use time::strptime;

    #[test]
    fn test_new_sigv4() {
        let sig = SigV4::new();
        assert_eq!(sig.headers.len(), 0)
    }

    #[test]
    fn test_date() {
        let sig = SigV4::new().date();
        assert_eq!(sig.headers[0].key.as_slice(), "X-Amz-Date")
    }

    #[test]
    fn test_add_header() {
        let h = Header{ key: "test".to_string(),
        value: "a string".to_string()};

        let sig = SigV4::new().header(h);
        assert_eq!(sig.headers[0].value.as_slice(), "a string")
    }

    #[test]
    fn test_hashed_request() {
        let h = Header{ key: "Content-Type".to_string(), value: "application/x-www-form-urlencoded; charset=utf-8".to_string() };
        let h2 = Header{ key: "Host".to_string(), value: "iam.amazonaws.com".to_string() };

        let sig = SigV4 {
            headers: vec![h, h2],
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
        }.date();

        assert_eq!(sig.hashed_canonical_request().as_slice(), "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2")
    }

    #[test]
    fn test_signed_headers() {
        let h = Header{ key: "test".to_string(),
            value: "a string".to_string()};
        let h2 = Header{ key: "Content-Type".to_string(),
            value: "application/x-www-form-urlencoded; charset=utf-8".to_string()};
        let h3 = Header{ key: "Authorization".to_string(),
            value: "none".to_string()};

        let mut sig = SigV4::new().date().header(h).header(h2).header(h3);
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
        let mut sig = SigV4::new().header(h).header(h2).header(h3).header(h4);
        assert_eq!(sig.canonical_headers().as_slice(), "abc:2\nmno:3\nxyz:1\n")
    }

    #[test]
    fn test_prune_whitespace() {
        let h = Header{ key: "Abc".to_string(), value: "a  b  c".to_string() };
        let mut sig = SigV4::new().header(h);
        assert_eq!(sig.canonical_headers().as_slice(), "abc:a b c\n")
    }

    #[test]
    fn test_no_prune_quoted() {
        let h = Header{ key: "Abc".to_string(), value: "\"a  b  c\"".to_string() };
        let mut sig = SigV4::new().header(h);
        assert_eq!(sig.canonical_headers().as_slice(), "abc:\"a  b  c\"\n")
    }

    #[test]
    fn test_specific_date() {
        let sig = SigV4 {
            headers: Vec::new(),
            path: None,
            method: None,
            query: None,
            payload: None,
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
        }.date();
        assert_eq!(sig.headers[0].value.as_slice(), "20110909T233600Z")
    }

    #[test]
    fn test_empty_canonical_request() {
        let sig = SigV4::new();
        assert_eq!(sig.canonical_request().as_slice(), "\n\n\n\n\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    #[test]
    fn test_canonical_request() {
        let h = Header{ key: "Content-Type".to_string(), value: "application/x-www-form-urlencoded; charset=utf-8".to_string() };
        let h2 = Header{ key: "Host".to_string(), value: "iam.amazonaws.com".to_string() };

        let sig = SigV4 {
            headers: vec![h, h2],
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
        }.date();

        assert_eq!(sig.canonical_request().as_slice(), r"POST
/

content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20110909T233600Z

content-type;host;x-amz-date
b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2")
    }

}
