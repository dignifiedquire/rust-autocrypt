use std::{fmt, str};
use std::collections::BTreeMap;

use types::{KeyType, EncryptPreference};

/// Represents an Autocrypt Header
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Header {
    /// The single recipient email address this header is valid for.
    pub addr: String,
    /// Key type
    pub typ: KeyType,
    /// Encryption preference,
    pub prefer_encrypt: EncryptPreference,
    /// Public Key, encoded in Base64
    pub keydata: String,
    /// All non default attributes, this is a `BTreeMap` to ensure consistent sorting
    attributes: BTreeMap<String, String>,
}

impl fmt::Display for Header {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut rest = String::new();
        for (key, value) in self.attributes.iter() {
            rest = format!("{}{}={}; ", rest, key, value);
        }

        write!(fmt,
               "addr={}; type={}; prefer-encrypt={}; {}keydata={}",
               self.addr,
               self.typ,
               self.prefer_encrypt,
               rest,
               self.keydata)
    }
}

impl Header {
    pub fn new(addr: String,
               typ: KeyType,
               pref: EncryptPreference,
               key: String,
               attributes: BTreeMap<String, String>)
               -> Header {
        Header {
            addr: addr,
            typ: typ,
            prefer_encrypt: pref,
            keydata: key,
            attributes: attributes,
        }
    }

    /// Get any additional attributes
    pub fn get<S: Into<String>>(&self, key: S) -> Option<&String> {
        self.attributes.get(&key.into())
    }
}

impl str::FromStr for Header {
    // TODO: proper error type
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut attributes: BTreeMap<String, String> = s.split(";")
            .filter_map(|a| {
                            let attribute: Vec<&str> = a.trim().split("=").collect();
                            if attribute.len() == 2 {
                                Some((attribute[0].to_string(), attribute[1].to_string()))
                            } else {
                                None
                            }
                        })
            .collect();

        if let Some(addr) = attributes.remove("addr") {
            if let Some(keydata) = attributes.remove("keydata") {
                let typ = attributes
                    .remove("type")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(KeyType::OpenPGP);

                let pref = attributes
                    .remove("prefer-encrypt")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(EncryptPreference::None);

                // Ensure no unkown critical attributes are present
                let crit_count = attributes
                    .keys()
                    .filter(|k| !k.starts_with("_"))
                    .count();
                if crit_count > 0 {
                    return Err(());
                }

                return Ok(Header::new(addr.to_string(),
                                      typ,
                                      pref,
                                      keydata.to_string(),
                                      attributes));
            }
        }

        Err(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn keydata() -> String {
        "mDMEWFUX7RYJKwYBBAHaRw8BAQdACHq6FkRGsHqBMsNpD7d+Q2jtxVwTO+Y4NhBaQyHaMj+0HWFsaWNlQHRlc3RzdWl0ZS5hdXRvY3J5cHQub3JniJAEExYIADgWIQQmqmdR/XZoxC+kkkr8dE2p/nPD1AUCWFUX7QIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRD8dE2p/nPD1EqOAP0WUDKwko001X7XTSYbWGWmXfR9P1Aw6917EnkVQMsp3gEA86Ii8ArL3jd+E2qS5JSysx/qiVhuTSwWzmC5K6zKdg+4OARYVRfuEgorBgEEAZdVAQUBAQdAv1A88FoCfwz0zSh6NNnUuKuz1p3ctJ3kXMGotsVYjA0DAQgHiHgEGBYIACAWIQQmqmdR/XZoxC+kkkr8dE2p/nPD1AUCWFUX7gIbDAAKCRD8dE2p/nPD1FTOAP4nS14sX7a/nBXBKWAh/oX8iVtkhmZqjy9tG21BcNqb+wEAq73H4+1ncnkscR3Nu4GYzNRSD3NXq68tEESK28kYvw4=".to_string()
    }

    #[test]
    fn test_to_string() {
        let h = Header::new("me@mail.com".to_string(),
                            KeyType::OpenPGP,
                            EncryptPreference::Mutual,
                            keydata(),
                            BTreeMap::new());

        assert_eq!(h.to_string(),
                   format!("addr=me@mail.com; type=1; prefer-encrypt=mutual; keydata={}",
                           keydata()));
    }

    #[test]
    fn test_from_str() {
        let h: Header = "addr=me@mail.com; type=1; prefer-encrypt=mutual; keydata=mykey"
            .parse()
            .expect("failed to parse");

        assert_eq!(h.addr, "me@mail.com");
        assert_eq!(h.typ, KeyType::OpenPGP);
        assert_eq!(h.prefer_encrypt, EncryptPreference::Mutual);
        assert_eq!(h.keydata, "mykey");
    }

    #[test]
    fn test_from_str_minimal() {
        let h: Header = "addr=me@mail.com; keydata=mykey"
            .parse()
            .expect("failed to parse");

        assert_eq!(h.addr, "me@mail.com");
        assert_eq!(h.typ, KeyType::OpenPGP);
        assert_eq!(h.prefer_encrypt, EncryptPreference::None);
        assert_eq!(h.keydata, "mykey");
    }

    #[test]
    fn test_from_str_non_critical() {
        let raw = "addr=me@mail.com; _foo=one; _bar=two; keydata=mykey";
        let h: Header = raw.parse().expect("failed to parse");

        assert_eq!(h.addr, "me@mail.com");
        assert_eq!(h.typ, KeyType::OpenPGP);
        assert_eq!(h.prefer_encrypt, EncryptPreference::None);
        assert_eq!(h.keydata, "mykey");
        assert_eq!(h.get("_foo").unwrap(), "one");
        assert_eq!(h.get("_bar").unwrap(), "two");

        assert_eq!(h.to_string(),
                   "addr=me@mail.com; type=1; prefer-encrypt=nopreference; _bar=two; _foo=one; keydata=mykey");
    }

    #[test]
    fn test_from_str_superflous_critical() {
        let raw = "addr=me@mail.com; _foo=one; _bar=two; other=me; keydata=mykey";
        raw.parse::<Header>()
            .expect_err("should have failed to parse");

    }
}
