use time::now_utc;
use time::Tm;
use std::ascii::AsciiExt;
use openssl::crypto::hash::Hasher;
use openssl::crypto::hash::HashType::SHA256;
use serialize::hex::ToHex;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use request::Header;
use url::percent_encoding::{percent_encode_to, FORM_URLENCODED_ENCODE_SET};

struct QP<'a> {
    k: &'a str,
    v: &'a str,
}

#[derive(Clone)]
pub struct SigV4 {
    headers: BTreeMap<String, Vec<String>>,
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
            headers: BTreeMap::new(),
            path: None,
            method: None,
            query: None,
            payload: None,
            date: dt,
        }
    }

    pub fn header(mut self, header: Header) -> SigV4 {
        append_header(&mut self.headers, header.key.as_slice(), header.value.as_slice());
        self
    }

    pub fn date(mut self) -> SigV4 {
        append_header(&mut self.headers, "X-Amz-Date",
                      self.date.strftime("%Y%m%dT%H%M%SZ").unwrap().to_string().as_slice());
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

    fn signed_headers(&self) -> String {
        let mut h = String::new();

        for (key,_) in self.headers.iter() {
            if h.len() > 0 {
                h.push(';')
            }
            if key.as_slice() == "authorization" {
                continue;
            }
            h.push_str(key.as_slice());
        }
        h
    }

    fn canonical_headers(&self) -> String {
        let mut h = String::new();

        for (key,value) in self.headers.iter() {
            if key.as_slice() == "authorization" {
                continue;
            }
            h.push_str(format!("{}:{}\n", key, canonical_value(value)).as_slice());
        }
        h
    }

    fn canonical_query_string(&self) -> String {
        match self.query {
            None => String::new(),
            Some(ref x) => {
                let mut h: Vec<QP> = Vec::new();
                for q in x.split('&') {
                    if q.contains_char('=') {
                        let n: Vec<&str> = q.splitn(1, '=').collect();
                        h.push(QP{k: n[0], v: n[1]})
                    } else {
                        h.push(QP{k: q, v: ""})
                    }
                };
                sort_query_string(h)
            }
        }
    }

    fn canonical_request(&self) -> String {
        format!("{}\n{}\n{}\n{}\n{}\n{}", expand_string(&self.method),
                expand_string(&self.path),
                self.canonical_query_string(),
                self.canonical_headers(),
                self.signed_headers(),
                self.hashed_payload()
        )
    }

}

fn sort_query_string(mut query: Vec<QP>) -> String {
    #[inline]
    fn byte_serialize(input: &str, output: &mut String) {
        for &byte in input.as_bytes().iter() {
            percent_encode_to(&[byte], FORM_URLENCODED_ENCODE_SET, output)
        }
    }

    let mut output = String::new();

    query.sort_by( |a, b| a.k.cmp(b.k));
    for item in query.iter() {
        if output.len() > 0 {
            output.push_str("&");
        }
        byte_serialize(item.k, &mut output);
        output.push_str("=");
        byte_serialize(item.v, &mut output);
    }

    output
    // it would be marvelous to use the below, but the AWS SigV4 spec says space must be %20, and
    // rust-url gives me back a +. So, roll our own for now.
    // let qs: Vec<(String, String)> = query.iter().map(|n| (n.k.to_string(), n.v.to_string())).collect();
    // form_urlencoded::serialize_owned(qs.as_slice())
}

fn append_header(map: &mut BTreeMap<String, Vec<String>>, key: &str, value: &str) {
    let k = key.to_ascii_lowercase().to_string();

    match map.entry(k) {
        Entry::Vacant(entry) => {
            let mut values = Vec::new();
            values.push(value.to_string());
            entry.set(values);
        },
        Entry::Occupied(entry) => {
            entry.into_mut().push(value.to_string());
        }
    };
}

fn expand_string(val: &Option<String>) -> String {
    match *val {
        None => "".to_string(),
        Some(ref x) => x.to_string(),
    }
}

fn canonical_value(val: &Vec<String>) -> String {
    let mut st = String::new();
    for v in val.iter() {
        if st.len() > 0 {
            st.push(',')
        }
        if v.starts_with("\""){
            st.push_str(v.as_slice());
        } else {
            st.push_str(v.replace("  ", " ").trim());
        }
    }
    st
}

#[cfg(test)]
mod tests {
    use super::SigV4;
    use request::Header;
    use time::strptime;
    use std::collections::BTreeMap;

    macro_rules! wrap_header (
        ($key:expr) => (
            Some(&vec!($key.to_string()))
        )
    );

    #[test]
    fn test_new_sigv4() {
        let sig = SigV4::new();
        assert_eq!(sig.headers.len(), 0)
    }

    #[test]
    fn test_date() {
        let sig = SigV4::new().date();
        assert!(sig.headers.contains_key("x-amz-date"))
    }

    #[test]
    fn test_add_header() {
        let h = Header{ key: "test".to_string(), value: "a string".to_string()};

        let sig = SigV4::new().header(h);
        assert_eq!(sig.headers.get("test"), wrap_header!("a string"))
    }

    #[test]
    fn test_add_second_value() {
        let h = Header{ key: "test".to_string(), value: "a string".to_string()};
        let h2 = Header{ key: "test".to_string(), value: "another string".to_string()};

        let sig = SigV4::new().header(h).header(h2);
        assert_eq!(sig.headers.get("test"), Some(&vec!("a string".to_string(), "another string".to_string())))
    }

    #[test]
    fn test_canonical_query_encoded() {
        let sig = SigV4::new().query("a space=woo woo&x-amz-header=foo".to_string());
        assert_eq!(sig.canonical_query_string().as_slice(), "a%20space=woo%20woo&x-amz-header=foo")
    }

    #[test]
    fn test_canonical_query_valueless() {
        let sig = SigV4::new().query("other=&test&x-amz-header=foo".to_string());
        assert_eq!(sig.canonical_query_string().as_slice(), "other=&test=&x-amz-header=foo")
    }

    #[test]
    fn test_canonical_query_sorted() {
        let sig = SigV4::new().query("foo=&bar=&baz=".to_string());
        assert_eq!(sig.canonical_query_string().as_slice(), "bar=&baz=&foo=")
    }

    // Ensure that params with the same name stay in the same order after sorting
    #[test]
    fn test_canonical_query_complex() {
        let sig = SigV4::new().query("q.options=abc&q=xyz&q=mno".to_string());
        assert_eq!(sig.canonical_query_string().as_slice(), "q=xyz&q=mno&q.options=abc")
    }

    #[test]
    fn test_hashed_request() {
        let h = Header{ key: "Content-Type".to_string(), value: "application/x-www-form-urlencoded; charset=utf-8".to_string() };
        let h2 = Header{ key: "Host".to_string(), value: "iam.amazonaws.com".to_string() };

        let sig = SigV4 {
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
        }.date().header(h).header(h2);

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

        let sig = SigV4::new().date().header(h).header(h2).header(h3);
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
    fn test_specific_date() {
        let sig = SigV4 {
            headers: BTreeMap::new(),
            path: None,
            method: None,
            query: None,
            payload: None,
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
        }.date();
        assert_eq!(sig.headers.get("x-amz-date"), wrap_header!("20110909T233600Z"))
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
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
        }.date().header(h).header(h2);

        assert_eq!(sig.canonical_request().as_slice(), r"POST
/

content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20110909T233600Z

content-type;host;x-amz-date
b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2")
    }

}
