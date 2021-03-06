use email;

quick_error! {
    #[derive(PartialEq, Eq, Debug, Clone)]
    pub enum HeaderParseError {
        UnknownCriticalAttributes {}
        MissingCriticalAttribute(descr: &'static str) {
            description(descr)
            display("Missing Critical Attribute: {}", descr)
        }
        MissingHeader {}
        TooManyHeaders {}
        InvalidHeader {}
    }
}
quick_error! {
    #[derive(PartialEq, Eq, Debug, Clone)]
    pub enum KeyTypeParseError {}
}

quick_error! {
    #[derive(PartialEq, Eq, Debug, Clone)]
    pub enum EncryptPreferenceParseError {}
}

quick_error! {
    #[derive(PartialEq, Eq, Debug, Clone)]
    pub enum PeerInfoParseError {
        MimeError {
            from(email::results::ParsingError)
        }

        HeaderError {
            from(HeaderParseError)
        }
    }
}
