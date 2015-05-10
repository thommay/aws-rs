use hyper;
use signers::sigv4::SigV4;
use credentials::Credentials;

#[derive(Debug)]
pub struct APIClient {
    signer: Option<SigV4>
}

impl APIClient {
    pub fn new(creds: Credentials, region: &str, service: &str) -> APIClient{
        let sig = SigV4::new();
        let sig = sig.credentials(creds);
        let sig = sig.region(region);
        let sig = sig.service(service);

        let host = format!("{}.{}.amazonaws.com", service, region);
        let sig = sig.header(("Host", &host));

        APIClient {
            signer: Some(sig)
        }
    }
}
