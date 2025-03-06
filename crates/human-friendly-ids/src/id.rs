// src/id.rs
//! Core ID type and associated operations

use std::{fmt, str::FromStr};

use crate::{
    alphabet::{self, CHECK_ALPHABET},
    error::IdError,
};

/// A user-friendly identifier with check bit validation
///
/// # Example
/// ```no_run
/// use human_friendly_ids::UploadId;
/// use std::str::FromStr;
///
/// let id = UploadId::from_str("abc-").unwrap();
/// assert_eq!(id.as_str(), "abc-");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UploadId(pub(crate) String);

impl UploadId {
    /// Get string slice representation
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Calculate maximum valid ID length for current configuration
    #[allow(clippy::arithmetic_side_effects, reason = "assert macro")]
    pub const fn max_length() -> usize {
        const _: () = assert!(
            CHECK_ALPHABET.len() > 2,
            "CHECK_ALPHABET length must be greater than 2"
        );
        let max_value = u64::MAX / (CHECK_ALPHABET.len() - 1) as u64;
        (max_value + 1) as usize
    }
}

impl AsRef<str> for UploadId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::ops::Deref for UploadId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl From<UploadId> for String {
    fn from(id: UploadId) -> Self {
        id.0
    }
}

impl From<UploadId> for Box<str> {
    fn from(id: UploadId) -> Self {
        id.0.into_boxed_str()
    }
}

impl FromStr for UploadId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = alphabet::normalize_string(s);

        if normalized.len() < 2 {
            return Err(IdError::TooShort);
        }

        let (body, check_char) = normalized
            .split_at_checked(normalized.len().checked_sub(1).expect("checked above"))
            .ok_or(IdError::InvalidCharacter)?;
        let expected_check = alphabet::calculate_check_char(body)?;

        if check_char != expected_check.to_string() {
            return Err(IdError::InvalidCheckBit);
        }

        body.chars().try_for_each(alphabet::validate_char)?;

        Ok(Self(normalized))
    }
}

impl TryFrom<String> for UploadId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl fmt::Display for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "serde")]
/// This module provides custom implementations for the `Serialize` and `Deserialize` traits
/// for the `UploadId` type. These implementations allow `UploadId` to be serialized as a string
/// and deserialized from a string using Serde.
///
/// # Examples
///
/// ```
/// use serde::{Serialize, Deserialize};
/// use human_friendly_ids::UploadId;
///
/// #[derive(Serialize, Deserialize)]
/// struct MyStruct {
///     id: UploadId,
/// }
/// ```
///
/// For further information, visit [Clippy's missing_docs_in_private_items](https://rust-lang.github.io/rust-clippy/master/index.html#missing_docs_in_private_items).
mod serde_impl {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    use super::UploadId;

    impl Serialize for UploadId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(self.as_str())
        }
    }

    impl<'de> Deserialize<'de> for UploadId {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(D::Error::custom)
        }
    }
}
