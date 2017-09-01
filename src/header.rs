use std::{fmt, str};
use std::collections::HashMap;

use types::{KeyType, EncryptPreference};

/// Represents an Autocrypt Header
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Header {
    /// The single recipient email address this header is valid for.
    pub addr: String,
    /// Key type
    pub typ: Option<KeyType>,
    /// Encryption preference,
    pub prefer_encrypt: Option<EncryptPreference>,
    /// Public Key, encoded in Base64
    pub keydata: String,
}

impl fmt::Display for Header {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut res = format!("addr={};", self.addr);

        if let Some(ref typ) = self.typ {
            res = format!("{} type={};", res, typ);
        }

        if let Some(ref pref) = self.prefer_encrypt {
            res = format!("{} prefer-encrypt={};", res, pref)
        }

        write!(fmt, "{} keydata={}", res, self.keydata)
    }
}

impl Header {
    pub fn new(addr: String,
               typ: Option<KeyType>,
               pref: Option<EncryptPreference>,
               key: String)
               -> Header {
        Header {
            addr: addr,
            typ: typ,
            prefer_encrypt: pref,
            keydata: key,
        }
    }
}

impl str::FromStr for Header {
    // TODO: proper error type
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let attributes: HashMap<&str, &str> = s.split(";")
            .filter_map(|a| {
                            let attribute: Vec<&str> = a.trim().split("=").collect();
                            if attribute.len() == 2 {
                                Some((attribute[0], attribute[1]))
                            } else {
                                None
                            }
                        })
            .collect();

        if let Some(addr) = attributes.get("addr") {
            if let Some(keydata) = attributes.get("keydata") {
                let typ = attributes.get("type").and_then(|s| s.parse().ok());

                let pref = attributes
                    .get("prefer-encrypt")
                    .and_then(|s| s.parse().ok());

                return Ok(Header::new(addr.to_string(), typ, pref, keydata.to_string()));
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
    fn test_fmt() {
        let h = Header::new("me@mail.com".to_string(),
                            Some(KeyType::OpenPGP),
                            Some(EncryptPreference::Mutual),
                            keydata());

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
        assert_eq!(h.typ, Some(KeyType::OpenPGP));
        assert_eq!(h.prefer_encrypt, Some(EncryptPreference::Mutual));
        assert_eq!(h.keydata, "mykey");
    }
}
