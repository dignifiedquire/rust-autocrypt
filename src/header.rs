use std::fmt;
// use std::collections::HashMap;

/// What type of key is used.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum KeyType {
    /// OpenPGP Key, serializes to `1`.
    OpenPGP,
    /// Any other key type, renders the header invalid.
    Unknown(String),
}

impl fmt::Display for KeyType {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyType::OpenPGP => write!(fmt, "1"),
            KeyType::Unknown(ref str) => write!(fmt, "{}", str),
        }
    }
}

/// Possible values for encryption preference
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum EncryptPreference {
    Mutual,
}

impl fmt::Display for EncryptPreference {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EncryptPreference::Mutual => write!(fmt, "mutual"),
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt() {
        let keydata = "mDMEWFUX7RYJKwYBBAHaRw8BAQdACHq6FkRGsHqBMsNpD7d+Q2jtxVwTO+Y4NhBaQyHaMj+0HWFsaWNlQHRlc3RzdWl0ZS5hdXRvY3J5cHQub3JniJAEExYIADgWIQQmqmdR/XZoxC+kkkr8dE2p/nPD1AUCWFUX7QIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRD8dE2p/nPD1EqOAP0WUDKwko001X7XTSYbWGWmXfR9P1Aw6917EnkVQMsp3gEA86Ii8ArL3jd+E2qS5JSysx/qiVhuTSwWzmC5K6zKdg+4OARYVRfuEgorBgEEAZdVAQUBAQdAv1A88FoCfwz0zSh6NNnUuKuz1p3ctJ3kXMGotsVYjA0DAQgHiHgEGBYIACAWIQQmqmdR/XZoxC+kkkr8dE2p/nPD1AUCWFUX7gIbDAAKCRD8dE2p/nPD1FTOAP4nS14sX7a/nBXBKWAh/oX8iVtkhmZqjy9tG21BcNqb+wEAq73H4+1ncnkscR3Nu4GYzNRSD3NXq68tEESK28kYvw4=";

        let h = Header::new("me@mail.com".to_string(),
                            Some(KeyType::OpenPGP),
                            Some(EncryptPreference::Mutual),
                            keydata.to_string());

        assert_eq!(h.to_string(),
                   format!("addr=me@mail.com; type=1; prefer-encrypt=mutual; keydata={}",
                           keydata));
    }
}
