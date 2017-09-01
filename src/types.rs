use std::{fmt, str};

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

impl str::FromStr for KeyType {
    // TODO: proper error type
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1" => Ok(KeyType::OpenPGP),
            _ => Ok(KeyType::Unknown(s.to_string())),
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

impl str::FromStr for EncryptPreference {
    // TODO: proper error type
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mutual" => Ok(EncryptPreference::Mutual),
            _ => Err(()),
        }
    }
}
