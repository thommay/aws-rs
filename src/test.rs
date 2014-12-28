// extern crate testing;

use glacier::{SigV4, Header};

#[test]
fn test_new_sigv4() {
    let sig = SigV4::new();
    assert_eq!(sig.headers().len(), 0)
}

#[test]
fn test_add_header() {
    let h = Header{ key: "test".to_string(),
                    value: "a string".to_string()};

    let sig = SigV4::new().header(h);
    assert_eq!(sig.headers()[0].value.as_slice(), "a string")
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
