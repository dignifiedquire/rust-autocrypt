use std::{fmt, str};

use errors::{KeyTypeParseError, EncryptPreferenceParseError};

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
    type Err = KeyTypeParseError;

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
    None,
}

impl fmt::Display for EncryptPreference {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EncryptPreference::Mutual => write!(fmt, "mutual"),
            EncryptPreference::None => write!(fmt, "nopreference"),
        }
    }
}

impl str::FromStr for EncryptPreference {
    type Err = EncryptPreferenceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mutual" => Ok(EncryptPreference::Mutual),
            _ => Ok(EncryptPreference::None),
        }
    }
}
