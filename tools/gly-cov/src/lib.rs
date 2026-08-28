

use std::fmt;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoverageReport {
    
    pub messages: usize,
    
    pub verified: usize,
}

impl fmt::Display for CoverageReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Protokol kapsam raporu: {} mesaj / {} doğrulanmış",
            self.messages, self.verified
        )
    }
}

#[must_use]
pub const fn empty_report() -> CoverageReport {
    CoverageReport {
        messages: 0,
        verified: 0,
    }
}
