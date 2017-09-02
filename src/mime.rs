use email::{self, MimeMessage};
use header::Header;
use errors::HeaderParseError;
use time;

// example: Sat, 17 Dec 2016 10:07:48 +0100
pub static EMAIL_DATE_FMT: &'static str = "%a, %d %b %Y %T %z";

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
pub fn get_ac_header(mail: &MimeMessage) -> Result<Option<Header>, HeaderParseError> {
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

/// Get the effective date of this email.
///
/// If an error occurs while trying to fetch the date from the email
/// it will fallback to the current time.
pub fn get_effective_date(mail: &MimeMessage) -> time::Tm {
    let date = mail.headers.get_value::<String>("Date".to_string());
    if date.is_err() {
        return time::now_utc();
    }
    // we already checked that we don't have an error, so save to expect
    match time::strptime(&date.expect("impossible"), EMAIL_DATE_FMT) {
        Ok(date) => date.to_utc(),
        Err(_) => time::now_utc(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helpers::*;

    #[test]
    fn test_parse_simple() {
        let file = get_file("rsa2048-simple.eml");
        parse(&file).expect("failed to parse");
    }

    #[test]
    fn test_get_ac_header() {
        let file = get_file("rsa2048-simple.eml");
        let mail = parse(&file).expect("failed to parse");

        let header = get_ac_header(&mail)
            .expect("failed to get ac header")
            .unwrap();
        assert_eq!(header.addr, "alice@testsuite.autocrypt.org");
    }

    #[test]
    fn test_get_ac_header_missing() {
        let file = get_file("no-autocrypt.eml");
        let mail = parse(&file).expect("failed to parse");

        let header = get_ac_header(&mail).expect("failed to get ac header");
        assert!(header.is_none());
    }

    #[test]
    fn test_get_effective_time() {
        let file = get_file("no-autocrypt.eml");
        let mail = parse(&file).expect("failed to parse");

        assert_eq!(get_effective_date(&mail),
                   time::strptime("Sat, 17 Dec 2016 10:51:48 +0100", EMAIL_DATE_FMT)
                       .expect("failed to parse")
                       .to_utc())
    }
}
