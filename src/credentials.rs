use ini::Ini;
use std::os;

#[derive(Clone)]
pub struct Credentials<'a> {
    pub key: Option<String>,
    pub secret: Option<String>,
    path: String,
    profile: String,
}

impl<'a> Credentials<'a> {
    pub fn new() -> Credentials<'a> {
        Credentials{
            key: None,
            secret: None,
            path: get_profile_path(),
            profile: get_default_profile(),
        }
    }

    pub fn path(mut self, path: &str) -> Credentials<'a > {
        self.path = get_absolute_path(path);
        self
    }

    pub fn profile(mut self, profile: &str) -> Credentials<'a> {
        self.profile = String::from_str(profile);
        self
    }

    pub fn load(mut self) -> Credentials<'a> {
        let mut conf = Ini::load_from_file(self.path.as_slice()).unwrap();
        conf.begin_section(self.profile.as_slice());
        let key = conf.get("aws_access_key_id").unwrap();
        let secret = conf.get("aws_secret_access_key").unwrap();

        self.key = Some(key.to_string());
        self.secret = Some(secret.to_string());
        self
    }
}

fn get_default_profile() -> String {
    match os::getenv("AWS_PROFILE") {
        None => "default".to_string(),
        Some(s) => s.to_string(),
    }
}

fn get_profile_path() -> String {
    let home = match os::getenv("HOME") {
        // hell if i know what not having home set means
        None => "/root".to_string(),
        Some(s) => s,
    };
    let p = Path::new(home).join(".aws").join("credentials");
    p.as_str().unwrap().to_string()
}

fn get_absolute_path(val: &str) -> String {
    let mut p = Path::new(val);
    p = os::make_absolute(&p).unwrap();
    p.as_str().unwrap().to_string()
}

#[cfg(test)]
mod test {
    use super::Credentials;

    #[test]
    fn test_defaults() {
        let cred = Credentials::new().path("/my/credentials/file");
        assert_eq!(cred.path.as_slice(), "/my/credentials/file")
    }

    #[test]
    fn test_profile() {
        let cred = Credentials::new().profile("new");
        assert_eq!(cred.profile.as_slice(), "new")
    }

    #[test]
    fn test_load_default() {
        // the path is relative from where cargo is running, so the root of the project
        let cred = Credentials::new().path("fixtures/credentials.ini").load();
        assert_eq!(cred.key.unwrap().as_slice(), "12345")
    }

    #[test]
    fn test_load_specific() {
        let cred = Credentials::new().path("fixtures/credentials.ini").profile("first").load();
        assert_eq!(cred.key.unwrap().as_slice(), "zxspectrum")
    }
}
