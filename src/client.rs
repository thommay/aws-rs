use curl::http;
use signers::sigv4::SigV4;

struct Client<'a, 'b> {
    signer: Option<SigV4<'a, 'b>>,
    handle: http::Handle
}

impl<'a, 'b> Client<'a, 'b> {
    pub fn new() -> Client<'a, 'b> {
        Client {
            signer: None,
            handle: http::Handle::new(),
        }
    }

    pub fn get(&self, host: String, path: String, payload: String) {
    }
}
