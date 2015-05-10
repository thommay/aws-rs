use ini::Ini;
use std::path::PathBuf;
use std::env;

#[derive(Clone,Debug)]
pub struct Credentials {
    pub key: Option<String>,
    pub secret: Option<String>,
    path: String,
    profile: String,
}

impl<'a> Credentials {
    pub fn new() -> Credentials {
        Credentials{
            key: None,
            secret: None,
            path: get_profile_path(),
            profile: get_default_profile(),
        }
    }

    pub fn path(mut self, path: &str) -> Credentials {
        self.path = get_absolute_path(path);
        self
    }

    pub fn profile(mut self, profile: &str) -> Credentials {
        self.profile = String::from_str(profile);
        self
    }

    pub fn load(mut self) -> Credentials {
        let mut conf = Ini::load_from_file(&self.path).unwrap();
        conf.begin_section(&self.profile);
        let key = conf.get("aws_access_key_id").unwrap();
        let secret = conf.get("aws_secret_access_key").unwrap();

        self.key = Some(key.to_string());
        self.secret = Some(secret.to_string());
        self
    }
}

fn get_default_profile() -> String {
    match env::var("AWS_PROFILE") {
        Err(_) => "default".to_string(),
        Ok(s) => s.to_string(),
    }
}

fn get_profile_path() -> String {
    let home = match env::var("HOME") {
        // hell if i know what not having home set means
        Err(_) => "/root".to_string(),
        Ok(s) => s,
    };
    let mut p = PathBuf::from(&home);
    p.push(".aws");
    p.push("credentials");
    p.to_str().unwrap().to_string()
}

fn get_absolute_path(val: &str) -> String {
    let mut p = PathBuf::from(val);
    if !p.is_absolute() {
        p = env::current_dir().unwrap();
        p.push(val);
    }
    p.to_str().unwrap().to_string()
}

#[cfg(test)]
mod test {
    use super::Credentials;

    #[test]
    fn test_defaults() {
        let cred = Credentials::new().path("/my/credentials/file");
        assert_eq!(cred.path, "/my/credentials/file")
    }

    #[test]
    fn test_profile() {
        let cred = Credentials::new().profile("new");
        assert_eq!(cred.profile, "new")
    }

    #[test]
    fn test_load_default() {
        // the path is relative from where cargo is running, so the root of the project
        let cred = Credentials::new().path("fixtures/credentials.ini").load();
        assert_eq!(cred.key.unwrap(), "12345")
    }

    #[test]
    fn test_load_specific() {
        let cred = Credentials::new().path("fixtures/credentials.ini").profile("first").load();
        assert_eq!(cred.key.unwrap(), "zxspectrum")
    }
}
