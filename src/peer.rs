use time::{self, Tm, Duration};
use std::fmt;
use email::MimeMessage;
use mime::{get_effective_date, get_ac_header};
use types::{KeyType, EncryptPreference, Recommendation};
use errors::PeerInfoParseError;

/// Internal state kept about a single peer
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PeerInfo {
    // required attributes
    /// UTC timestamp of the most recent effective date of all processed messages.
    pub last_seen: Tm,
    /// UTC timestamp of the most recent effective date of all processed messages that contained a valid Autocrypt header.
    pub last_seen_autocrypt: Option<Tm>,
    /// The public key of this peer.
    pub public_key: Option<String>,
    /// The current encryption preference.
    pub state: PeerState,
    /// For which autocrypt level this record is.
    pub typ: KeyType,
    // TODO: optional attributes
}

/// Possible values for encryption preference
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum PeerState {
    Mutual,
    None,
    Reset,
    Gossip,
}

impl fmt::Display for PeerState {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PeerState::Mutual => write!(fmt, "mutual"),
            PeerState::None => write!(fmt, "nopreference"),
            PeerState::Reset => write!(fmt, "reset"),
            PeerState::Gossip => write!(fmt, "gossip"),
        }
    }
}

impl PeerInfo {
    pub fn new(seen: Tm,
               seen_ac: Option<Tm>,
               key: Option<String>,
               state: Option<PeerState>)
               -> PeerInfo {
        PeerInfo {
            last_seen: seen,
            last_seen_autocrypt: seen_ac,
            public_key: key,
            state: state.unwrap_or(PeerState::None),
            // Current spec is always level 1
            typ: KeyType::OpenPGP,
        }
    }

    /// Update the current `PeerInfo` based on the passed in email.
    /// This manipulates the `self` in place.
    pub fn update<'a>(&mut self, mail: &MimeMessage) -> Result<(), PeerInfoParseError> {
        // multipart/report content type is to be ignored
        let content_type: String = mail.headers.get_value("Content-Type".to_string())?;
        if content_type == "multipart/report" {
            return Ok(());
        }

        let eff_date = get_effective_date(mail);
        let ac_header = get_ac_header(mail)?;

        if let Some(last_seen_ac) = self.last_seen_autocrypt {
            if eff_date < last_seen_ac {
                return Ok(());
            }
        }

        if ac_header.is_none() {
            if eff_date > self.last_seen {
                self.last_seen = eff_date;
                self.state = PeerState::Reset;
            }
            return Ok(());
        }

        // safe, as already checked above
        let ac_header = ac_header.unwrap();

        self.public_key = Some(ac_header.keydata);
        self.last_seen_autocrypt = Some(eff_date);

        if eff_date > self.last_seen {
            match ac_header.prefer_encrypt {
                EncryptPreference::Mutual => {
                    self.state = PeerState::Mutual;
                }
                _ => {
                    self.state = PeerState::None;
                }
            }
        }

        Ok(())
    }

    /// Get the autocrypt recommendation based on `self` being the from details.
    pub fn recommendation(&self, to: &PeerInfo) -> Recommendation {
        if to.public_key.is_none() {
            return Recommendation::Disable;
        }

        if self.state == PeerState::Mutual && to.state == PeerState::Mutual {
            return Recommendation::Encrypt;
        }

        if to.state == PeerState::Gossip {
            return Recommendation::Discourage;
        }

        if let Some(seen_ac) = to.last_seen_autocrypt {
            if to.state == PeerState::Reset && seen_ac < time::now_utc() - Duration::weeks(4) {
                return Recommendation::Discourage;
            }
        }

        Recommendation::Available
    }

    /// Get recommendations for sending to all the peers in `tos`.
    pub fn recommendation_many(&self, tos: Vec<&PeerInfo>) -> Recommendation {
        let mut recs = tos.iter().map(|to| self.recommendation(to));
        if recs.any(|rec| rec == Recommendation::Disable) {
            return Recommendation::Disable;
        }

        if recs.all(|rec| rec == Recommendation::Encrypt) {
            return Recommendation::Encrypt;
        }

        if recs.any(|rec| rec == Recommendation::Discourage) {
            return Recommendation::Discourage;
        }

        Recommendation::Available
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helpers;
    use mime;

    #[test]
    fn test_update_report() {
        let mut p1 = PeerInfo::new(time::now_utc(), None, None, None);
        let file = helpers::get_file("report.eml");
        let mail = mime::parse(&file).expect("failed to parse");
        let before = p1.clone();
        p1.update(&mail).expect("failed to update");
        assert_eq!(before, p1);
    }

    #[test]
    fn test_update_with_ac() {
        let mut p1 = PeerInfo::new(time::now_utc(), None, None, None);
        let file = helpers::get_file("rsa2048-simple.eml");
        let mail = mime::parse(&file).expect("failed to parse");
        p1.update(&mail).expect("failed to update");
        assert_eq!(p1.last_seen_autocrypt.unwrap(),
                   time::strptime("Sat, 17 Dec 2016 10:07:48 +0100", mime::EMAIL_DATE_FMT)
                       .expect("failed to parse")
                       .to_utc());
        assert!(p1.public_key.is_some());
        assert_eq!(p1.state, PeerState::None);
    }

    #[test]
    fn test_update_without_ac() {
        let time = time::Timespec::new(1234567890, 54321);
        let start = time::at_utc(time);

        let mut p1 = PeerInfo::new(start, None, None, None);
        let file = helpers::get_file("no-autocrypt.eml");
        let mail = mime::parse(&file).expect("failed to parse");
        p1.update(&mail).expect("failed to update");
        assert_eq!(p1.last_seen,
                   time::strptime("Sat, 17 Dec 2016 10:51:48 +0100", mime::EMAIL_DATE_FMT)
                       .expect("failed to parse")
                       .to_utc());
        assert!(p1.last_seen_autocrypt.is_none());
        assert!(p1.public_key.is_none());
        assert_eq!(p1.state, PeerState::Reset);
    }

    #[test]
    fn test_recommendation() {
        let p1 = PeerInfo::new(time::now_utc(), None, None, None);
        let p2 = PeerInfo::new(time::now_utc(),
                               None,
                               Some("mypublickey".to_string()),
                               Some(PeerState::Gossip));
        let p3 = PeerInfo::new(time::now_utc(),
                               None,
                               Some("pubkey".to_string()),
                               Some(PeerState::Mutual));
        let p4 = PeerInfo::new(time::now_utc(),
                               Some(time::now_utc() - Duration::days(100)),
                               Some("pubkey".to_string()),
                               Some(PeerState::Reset));

        // No to public key
        assert_eq!(p2.recommendation(&p1), Recommendation::Disable);

        // both states are mutual
        assert_eq!(p3.recommendation(&p3), Recommendation::Encrypt);

        // to state is gossip
        assert_eq!(p1.recommendation(&p2), Recommendation::Discourage);

        // reset and older than a month
        assert_eq!(p3.recommendation(&p4), Recommendation::Discourage);
    }

    #[test]
    fn test_recommendation_many() {
        let from = PeerInfo::new(time::now_utc(),
                                 Some(time::now_utc()),
                                 Some("mypublickey".to_string()),
                                 Some(PeerState::Mutual));
        let to1 = PeerInfo::new(time::now_utc(),
                                Some(time::now_utc()),
                                Some("mypublickey".to_string()),
                                Some(PeerState::Mutual));
        let to2 = PeerInfo::new(time::now_utc(),
                                Some(time::now_utc()),
                                Some("mypublickey".to_string()),
                                Some(PeerState::Mutual));
        assert_eq!(from.recommendation_many(vec![&to1, &to2]),
                   Recommendation::Encrypt);
    }
}
