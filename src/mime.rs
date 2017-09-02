use email::{self, MimeMessage};
use header::Header;
use errors::HeaderParseError;

/// Parse a string as a mime message
pub fn parse(s: &str) -> email::results::ParsingResult<MimeMessage> {
    MimeMessage::parse(s)
}

/// Get the autocrypt header from a parsed email.
/// Possible outcomes are
/// - no header, `Ok(None)`
/// - one header, valid, `Ok(Header{...})`
/// - one header, invalid, `Err(...)`,
/// - multiple headers, always invalid, `Err(...)`
pub fn get_ac_header(mail: MimeMessage) -> Result<Option<Header>, HeaderParseError> {
    let headers = mail.headers.find(&"Autocrypt".to_string());
    if let Some(headers) = headers {
        if headers.len() > 1 {
            return Err(HeaderParseError::TooManyHeaders);
        }

        let header: String = headers[0]
            .get_value()
            .map_err(|_| HeaderParseError::InvalidHeader)?;

        return header.parse().map(|h| Some(h));
    }

    Ok(None)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    fn get_file<S: Into<String>>(filename: S) -> String {
        let filepath = format!("./test/fixtures/{}", filename.into());
        let mut f = File::open(filepath).expect("file not found");

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("something went wrong reading the file");

        contents
    }

    #[test]
    fn test_parse_simple() {
        let file = get_file("rsa2048-simple.eml");
        parse(&file).expect("failed to parse");
    }

    #[test]
    fn test_get_ac_header() {
        let file = get_file("rsa2048-simple.eml");
        let mail = parse(&file).expect("failed to parse");

        let header = get_ac_header(mail)
            .expect("failed to get ac header")
            .unwrap();
        assert_eq!(header.addr, "alice@testsuite.autocrypt.org");
    }

    #[test]
    fn test_get_ac_header_missing() {
        let file = get_file("no-autocrypt.eml");
        let mail = parse(&file).expect("failed to parse");

        let header = get_ac_header(mail).expect("failed to get ac header");
        assert!(header.is_none());
    }
}
