use hyper::Client;
use hyper::client::Response;
use hyper::Result as HyperResult;
use signers::sigv4::SigV4;
use credentials::Credentials;

#[derive(Debug)]
pub struct ApiClient {
    signer: SigV4,
    version: String,
    endpoint: String
}

impl ApiClient {
    pub fn new(creds: Credentials, version: &str, region: &str, service: &str) -> ApiClient{
        let sig = SigV4::new();
        let sig = sig.credentials(creds);
        let sig = sig.region(region);
        let sig = sig.service(service);

        let host = format!("{}.{}.amazonaws.com", service, region);
        let sig = sig.header(("Host", &host));

        ApiClient {
            signer: sig,
            version: String::from(version),
            endpoint: format!("https://{}/", host)
        }
    }

    pub fn get(self, action: &str) -> HyperResult<Response>{
        let sig = self.signer.clone();
        let sig = sig.method("GET");
        let sig = sig.path("/");
        let query = format!("Action={}&Version={}", action, self.version);
        let sig = sig.query(&query);
        let url = format!("{}?{}", self.endpoint, query);

        let headers = sig.as_headers();
        let client = Client::new();
        let res = client.get(&url).headers(headers).send();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::ApiClient;
    use credentials::Credentials;

    #[test]
    fn test_new_apiclient() {
        let cred = Credentials::new().path("fixtures/credentials.ini").load();
        let region = "eu-west-1";
        let service = "ec2";
        let version = "2015-04-15";

        let client = ApiClient::new(cred, version, region, service);
        assert_eq!(client.endpoint, "https://ec2.eu-west-1.amazonaws.com/")
    }
}
