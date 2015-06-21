use time::now_utc;
use time::Tm;
use std::ascii::AsciiExt;
use openssl::crypto::hash::hash;
use openssl::crypto::hmac::hmac;
use openssl::crypto::hash::Type::SHA256;
use serialize::hex::ToHex;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use url::percent_encoding::{percent_encode_to, FORM_URLENCODED_ENCODE_SET};
use hyper::header::Headers;
use std::str;

use credentials::Credentials;

#[derive(Clone,Debug)]
pub struct SigV4 {
    credentials: Option<Credentials>,
    date: Tm,
    headers: BTreeMap<String, Vec<Vec<u8>>>,
    method: Option<String>,
    path: Option<String>,
    payload: Option<String>,
    query: Option<String>,
    region: Option<String>,
    service: Option<String>,
}

impl<'a> SigV4 {
    pub fn new() -> SigV4{
        let dt = now_utc();
        SigV4 {
            credentials: None,
            date: dt,
            headers: BTreeMap::new(),
            method: None,
            path: None,
            payload: None,
            query: None,
            region: None,
            service: None,
        }
    }

    pub fn header(mut self, header: (&str, &str)) -> SigV4 {
        append_header(&mut self.headers, header.0, header.1);
        self
    }

    pub fn credentials(mut self, credentials: Credentials) -> SigV4 {
        self.credentials = Some(credentials);
        self
    }

    pub fn path(mut self, path: &str) -> SigV4 {
        let path = String::from(path);
        self.path = Some(path);
        self
    }

    pub fn method(mut self, method: &str) -> SigV4 {
        let method = String::from(method);
        self.method = Some(method);
        self
    }

    pub fn query(mut self, query: &str) -> SigV4 {
        let query = String::from(query);
        self.query = Some(query);
        self
    }

    pub fn payload(mut self, payload: &str) -> SigV4 {
        let payload = String::from(payload);
        self.payload = Some(payload);
        self
    }

    pub fn region(mut self, region: &str) -> SigV4 {
        let region = String::from(region);
        self.region = Some(region);
        self
    }

    pub fn service(mut self, service: &str) -> SigV4 {
        let service = String::from(service);
        self.service = Some(service);
        self
    }

    fn date(mut self) -> SigV4 {
        append_header(&mut self.headers, "x-amz-date",
                      self.date.strftime("%Y%m%dT%H%M%SZ").unwrap().to_string().as_ref());
        self
    }

    fn authorization(mut self) -> SigV4 {
        let cs = self.credential_scope();
        let h = self.signed_headers();
        let s = self.clone().signature();

        let auth = format!("AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
               self.clone().credentials.unwrap().key.unwrap(),
               cs, h, s);

        debug!("Authorization header: {:?}", auth);
        append_header(&mut self.headers, "authorization", &auth);
        self
    }

    pub fn as_headers(self) -> Headers {
        let fin = self.date().authorization();
        let mut headers = Headers::new();

        for h in fin.headers {
            headers.set_raw(h.0, h.1);
        }
        headers
    }

    fn signature(self) -> String {
        hmac(SHA256, &self.derived_signing_key(),
             self.signing_string().as_bytes()).to_hex().to_string()
    }

    #[allow(non_snake_case)]
    fn derived_signing_key(&self) -> Vec<u8> {
        let kSecret = self.clone().credentials.unwrap().secret.unwrap();
        let kDate = hmac(SHA256, format!("AWS4{}", kSecret).as_bytes(),
                self.date.strftime("%Y%m%d").unwrap().to_string().as_bytes());
        let kRegion = hmac(SHA256, &kDate, expand_string(&self.region).as_bytes());
        let kService = hmac(SHA256, &kRegion, expand_string(&self.service).as_bytes());
        hmac(SHA256, &kService, "aws4_request".as_bytes())
    }

    fn signing_string(&self) -> String {
        format!("AWS4-HMAC-SHA256\n{}\n{}\n{}",
                self.date.strftime("%Y%m%dT%H%M%SZ").unwrap(),
                self.credential_scope(),
                self.hashed_canonical_request())
    }

    fn credential_scope(&self) -> String {
        format!("{}/{}/{}/aws4_request",
                self.date.strftime("%Y%m%d").unwrap(),
                expand_string(&self.region),
                expand_string(&self.service))
    }

    fn hashed_canonical_request(&self) -> String {
        to_hexdigest(self.canonical_request())
    }

    fn hashed_payload(&self) -> String {
        let val = match self.payload {
            Some(ref x) => x.to_string(),
            None => "".to_string(),
        };
        to_hexdigest(val)
    }

    fn signed_headers(&self) -> String {
        let mut h = String::new();

        for (key,_) in self.headers.iter() {
            if h.len() > 0 {
                h.push(';')
            }
            if skipped_headers(&key) {
                continue;
            }
            h.push_str(&key);
        }
        h
    }

    fn canonical_headers(&self) -> String {
        let mut h = String::new();

        for (key,value) in self.headers.iter() {
            if skipped_headers(&key) {
                continue;
            }
            h.push_str(format!("{}:{}\n", key, canonical_value(value)).as_ref());
        }
        h
    }

    fn canonical_query_string(&self) -> String {
        match self.query {
            None => String::new(),
            Some(ref x) => {
                let mut h: Vec<(&str, &str)> = Vec::new();
                for q in x.split('&') {
                    if q.contains('=') {
                        let n: Vec<&str> = q.splitn(2, '=').collect();
                        h.push((n[0], n[1]))
                    } else {
                        h.push((q, ""))
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

fn sort_query_string(mut query: Vec<(&str, &str)>) -> String {
    #[inline]
    fn byte_serialize(input: &str, output: &mut String) {
        for &byte in input.as_bytes().iter() {
            percent_encode_to(&[byte], FORM_URLENCODED_ENCODE_SET, output)
        }
    }

    let mut output = String::new();

    query.sort_by( |a, b| a.0.cmp(b.0));
    for item in query.iter() {
        if output.len() > 0 {
            output.push_str("&");
        }
        byte_serialize(item.0, &mut output);
        output.push_str("=");
        byte_serialize(item.1, &mut output);
    }

    output
    // it would be marvelous to use the below, but the AWS SigV4 spec says space must be %20, and
    // rust-url gives me back a +. So, roll our own for now.
    // let qs: Vec<(String, String)> = query.iter().map(|n| (n.k.to_string(), n.v.to_string())).collect();
    // form_urlencoded::serialize_owned(qs.as_slice())
}

fn append_header(map: &mut BTreeMap<String, Vec<Vec<u8>>>, key: &str, value: &str) {
    let k = key.to_ascii_lowercase().to_string();

    match map.entry(k) {
        Entry::Vacant(entry) => {
            let mut values = Vec::new();
            values.push(value.as_bytes().to_vec());
            entry.insert(values);
        },
        Entry::Occupied(entry) => {
            entry.into_mut().push(value.as_bytes().to_vec());
        }
    };
}

fn to_hexdigest(val: String) -> String {
    let h = hash(SHA256, val.as_bytes());
    h.as_slice().to_hex().to_string()
}

fn expand_string(val: &Option<String>) -> String {
    match *val {
        None => "".to_string(),
        Some(ref x) => x.to_string(),
    }
}

fn canonical_value(val: &Vec<Vec<u8>>) -> String {
    let mut st = String::new();
    for v in val {
        let s = str::from_utf8(v).unwrap();
        if st.len() > 0 {
            st.push(',')
        }
        if s.starts_with("\""){
            st.push_str(&s);
        } else {
            st.push_str(s.replace("  ", " ").trim());
        }
    }
    st
}

fn skipped_headers(header: &str) -> bool {
    ["authorization", "content-length", "user-agent" ].contains(&header)
}

#[cfg(test)]
mod tests {
    use super::SigV4;
    use signers::http_headers::*;
    use credentials::Credentials;
    use time::strptime;
    use std::collections::BTreeMap;
    use serialize::hex::ToHex;

    macro_rules! wrap_header (
        ($key:expr) => (
            Some(&vec!($key.as_bytes().to_vec()))
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
    fn test_add_credentials() {
        let cred = Credentials::new().path("fixtures/credentials.ini").load();
        let sig = SigV4::new().credentials(cred);

        let c = sig.credentials.unwrap();
        assert_eq!(c.key.unwrap(), "12345")
    }

    #[test]
    fn test_add_header() {
        let h = ("test", "a string");

        let sig = SigV4::new().header(h);
        assert_eq!(sig.headers.get("test"), wrap_header!("a string"))
    }

    #[test]
    fn test_add_second_value() {
        let h = ("test", "a string");
        let h2 = ("test", "another string");

        let sig = SigV4::new().header(h).header(h2);
        assert_eq!(sig.headers.get("test"), Some(&vec!("a string".as_bytes().to_vec(), "another string".as_bytes().to_vec())))
    }

    #[test]
    fn test_canonical_query_encoded() {
        let sig = SigV4::new().query("a space=woo woo&x-amz-header=foo");
        assert_eq!(sig.canonical_query_string(), "a%20space=woo%20woo&x-amz-header=foo")
    }

    #[test]
    fn test_canonical_query_valueless() {
        let sig = SigV4::new().query("other=&test&x-amz-header=foo");
        assert_eq!(sig.canonical_query_string(), "other=&test=&x-amz-header=foo")
    }

    #[test]
    fn test_canonical_query_sorted() {
        let sig = SigV4::new().query("foo=&bar=&baz=");
        assert_eq!(sig.canonical_query_string(), "bar=&baz=&foo=")
    }

    // Ensure that params with the same name stay in the same order after sorting
    #[test]
    fn test_canonical_query_complex() {
        let sig = SigV4::new().query("q.options=abc&q=xyz&q=mno");
        assert_eq!(sig.canonical_query_string(), "q=xyz&q=mno&q.options=abc")
    }

    #[test]
    fn test_signing_string() {
        let h = ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        let h2 = ("Host", "iam.amazonaws.com" );

        let sig = SigV4 {
            credentials: None,
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: Some("us-east-1".to_string()),
            service: Some("iam".to_string()),
        }.date().header(h).header(h2);

        assert_eq!(sig.signing_string(), r"AWS4-HMAC-SHA256
20110909T233600Z
20110909/us-east-1/iam/aws4_request
3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2")
    }

    #[test]
    fn test_hashed_request() {
        let h = ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8" );
        let h2 = ("Host", "iam.amazonaws.com" );

        let sig = SigV4 {
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            credentials: None,
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: None,
            service: None,
        }.date().header(h).header(h2);

        assert_eq!(sig.hashed_canonical_request(), "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2")
    }

    #[test]
    fn test_signed_headers() {
        let h = ("test", "a string");
        let h2 = ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        let h3 = ("Authorization", "none");

        let sig = SigV4::new().date().header(h).header(h2).header(h3);
        assert_eq!(sig.signed_headers(), "content-type;test;x-amz-date")
    }

    #[test]
    fn test_hashed_payload() {
        let sig = SigV4::new().
            payload("Action=ListUsers&Version=2010-05-08");
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
        let h = ("Xyz", "1");
        let h2 = ("Abc", "2");
        let h3 = ("Mno", "3");
        let h4 = ("Authorization", "4");
        let sig = SigV4::new().header(h).header(h2).header(h3).header(h4);
        assert_eq!(sig.canonical_headers(), "abc:2\nmno:3\nxyz:1\n")
    }

    #[test]
    fn test_prune_whitespace() {
        let h = ("Abc", "a  b  c");
        let sig = SigV4::new().header(h);
        assert_eq!(sig.canonical_headers(), "abc:a b c\n")
    }

    #[test]
    fn test_no_prune_quoted() {
        let h = ("Abc", "\"a  b  c\"");
        let sig = SigV4::new().header(h);
        assert_eq!(sig.canonical_headers(), "abc:\"a  b  c\"\n")
    }

    #[test]
    fn test_specific_date() {
        let sig = SigV4 {
            headers: BTreeMap::new(),
            path: None,
            method: None,
            query: None,
            payload: None,
            credentials: None,
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: None,
            service: None,
        }.date();
        assert_eq!(sig.headers.get("x-amz-date"), wrap_header!("20110909T233600Z"))
    }

    #[test]
    fn test_credential_scope() {
        let sig = SigV4 {
            headers: BTreeMap::new(),
            path: None,
            method: None,
            query: None,
            payload: None,
            credentials: None,
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: Some("eu-west-1".to_string()),
            service: Some("iam".to_string()),
        };
        assert_eq!(sig.credential_scope(), "20110909/eu-west-1/iam/aws4_request")
    }

    #[test]
    fn test_empty_canonical_request() {
        let sig = SigV4::new();
        assert_eq!(sig.canonical_request(), "\n\n\n\n\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    #[test]
    fn test_canonical_request() {
        let h = ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        let h2 = ("Host", "iam.amazonaws.com");

        let sig = SigV4 {
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            credentials: None,
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: None,
            service: None,
        }.date().header(h).header(h2);

        assert_eq!(sig.canonical_request(), r"POST
/

content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20110909T233600Z

content-type;host;x-amz-date
b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2")
    }


    #[test]
    fn test_signing_key() {
        let cred = Credentials::new().path("fixtures/credentials.ini").profile("aws").load();

        let sig = SigV4 {
            credentials: Some(cred),
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: Some("us-east-1".to_string()),
            service: Some("iam".to_string()),
        }.date();

        let target = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43, 171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229, 169, 76, 144, 239, 209, 227, 176, 231];
        assert_eq!(sig.derived_signing_key().to_hex(), target.to_hex())
    }

    #[test]
    fn test_signature() {
        let h = ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        let h2 = ("Host", "iam.amazonaws.com");

        let cred = Credentials::new().path("fixtures/credentials.ini").profile("aws").load();

        let sig = SigV4 {
            credentials: Some(cred),
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: Some("us-east-1".to_string()),
            service: Some("iam".to_string()),
        }.date().header(h).header(h2);

        assert_eq!(sig.signature(), "ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c")
    }

    #[test]
    fn test_auth_header() {
        let h = ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        let h2 = ("Host", "iam.amazonaws.com");

        let cred = Credentials::new().path("fixtures/credentials.ini").profile("aws").load();

        let sig = SigV4 {
            credentials: Some(cred),
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: Some("us-east-1".to_string()),
            service: Some("iam".to_string()),
        }.date().header(h).header(h2).authorization();

        assert_eq!(sig.headers.get("authorization"), wrap_header!("AWS4-HMAC-SHA256 Credential=akid/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c"))
    }

    #[test]
    fn test_as_headers() {
        let h = ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        let h2 = ("Host", "iam.amazonaws.com");

        let cred = Credentials::new().path("fixtures/credentials.ini").profile("aws").load();

        let sig = SigV4 {
            credentials: Some(cred),
            headers: BTreeMap::new(),
            path: Some("/".to_string()),
            method: Some("POST".to_string()),
            query: None,
            payload: Some("Action=ListUsers&Version=2010-05-08".to_string()),
            date: strptime("20110909T233600Z", "%Y%m%dT%H%M%SZ").unwrap(),
            region: Some("us-east-1".to_string()),
            service: Some("iam".to_string()),
        }.header(h).header(h2);

        let headers = sig.as_headers();

        assert_eq!(headers.get::<Authorization>().unwrap().to_string(), "AWS4-HMAC-SHA256 Credential=akid/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c".to_string())
    }
}
