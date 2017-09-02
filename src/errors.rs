quick_error! {
    #[derive(PartialEq, Eq, Debug, Clone)]
    pub enum HeaderParseError {
        UnknownCriticalAttributes {}
        MissingCriticalAttribute(descr: &'static str) {
            description(descr)
            display("Missing Critical Attribute: {}", descr)
        }
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