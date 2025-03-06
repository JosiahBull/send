// src/alphabet.rs
//! Character handling and validation for user-friendly IDs

use crate::error::IdError;

/// Primary generation alphabet (22 characters)
pub const GEN_ALPHABET: [char; 22] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'r', 's', 't', 'w', 'x',
    'y', '3', '4',
];

/// Check bit alphabet (23 characters, prime number length)
pub const CHECK_ALPHABET: [char; 23] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'r', 's', 't', 'w', 'x',
    'y', '3', '4', '-',
];

/// LUT for check alphabet character lookup
#[allow(clippy::indexing_slicing, reason = "const fn will fail early")]
const CHECK_LOOKUP: [u8; 256] = {
    let mut lookup = [0; 256];
    let mut i = 0;
    while i < CHECK_ALPHABET.len() {
        lookup[CHECK_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    lookup
};

/// Normalize potentially ambiguous characters
pub const fn normalize_char(c: char) -> char {
    match c {
        '0' => 'o',
        '1' | 'l' | '7' => 'i',
        '5' => 's',
        '2' => 'z',
        'u' => 'v',
        '6' | '8' | '9' | 'g' | 'q' => 'b',
        c => c,
    }
}

/// Normalize and replace ambiguous sequences in a string
pub fn normalize_string(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(normalize_char)
        .collect::<String>()
        .replace("rn", "m")
        .replace("vv", "w")
}

/// Validate a character against the check alphabet
pub fn validate_char(c: char) -> Result<(), IdError> {
    if CHECK_ALPHABET.contains(&c) {
        Ok(())
    } else {
        Err(IdError::InvalidCharacter)
    }
}

/// Calculate expected check character for a string
pub fn calculate_check_char(s: &str) -> Result<char, IdError> {
    let sum: u64 = s
        .chars()
        .map(|c| {
            CHECK_LOOKUP
                .get(c as usize)
                .copied()
                .ok_or(IdError::InvalidCharacter)
                .map(u64::from)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();

    let index = (sum
        .checked_rem(CHECK_ALPHABET.len() as u64)
        .ok_or(IdError::InvalidCheckBit)?) as usize;
    CHECK_ALPHABET
        .get(index)
        .copied()
        .ok_or(IdError::InvalidCheckBit)
}
