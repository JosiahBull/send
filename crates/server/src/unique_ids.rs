//! A tool for generating unique user-friendly IDs which are easy to write, read, remember, and
//! speak over the phone without being visually ambiguous.

use itertools::Itertools;
use rand::Rng;

/// The alphabet used to generate upload IDs.
const GEN_ALPHABET: [char; 22] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'r', 's', 't', 'w', 'x',
    'y', '3', '4',
];

/// The alphabet used for generating the check-bit.
/// NOTE: it is important that the length of the alphabet is a prime number, in this case 23 chars.
/// It must also be longer than the GEN_ALPHABET.
const CHECK_ALPHABET: [char; 23] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'r', 's', 't', 'w', 'x',
    'y', '3', '4', '=',
];

/// A lookup table for the check alphabet. This converts the check character as usize back
/// into a number from 1-23 (corresponding to the index in the check alpahabet)!
const CHECK_LOOKUP: [u64; 256] = {
    let mut lookup = [0_u64; 256];
    let mut i = 0;
    #[allow(
        clippy::indexing_slicing,
        reason = "This is a const fn, it will panic at compile time if out of bounds."
    )]
    while i < CHECK_ALPHABET.len() {
        lookup[CHECK_ALPHABET[i] as usize] = i as u64;
        assert!(i < u8::MAX as usize, "Index out of bounds");
        i += 1;
    }

    lookup
};

/// A unique identifier for uploads.
///
/// Designed to generate easily readable and pronounceable IDs for users, with correction check bits
/// to enable fast rejection on the frontend.
///
/// Uses the alphabet: `abcdefghijkmnoprstwxy34` with a check-bit from the alphabet `abcdefghijkmnoprstwxy34=`.
///
/// # Prior Art
/// * https://gajus.com/blog/avoiding-visually-ambiguous-characters-in-ids
///
/// # Examples
///
/// ```
/// use server_lib::unique_ids::UploadId;
///
/// // Generate a new UploadId
/// let new_id = UploadId::generate::<25>();
/// println!("Generated UploadId: {}", new_id);
///
/// // Try to decode a valid UploadId string
/// let valid_id_str = new_id.to_string();
/// let decoded_id = UploadId::try_decode(valid_id_str.clone()).expect("Failed to decode UploadId");
/// assert_eq!(decoded_id.to_string(), valid_id_str);
///
/// // Try to decode an invalid UploadId string
/// let invalid_id_str = "invalid_id_string".to_string();
/// let result = UploadId::try_decode(invalid_id_str);
/// assert!(result.is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct UploadId(String);

#[cfg_attr(test, mutants::skip)]
impl From<UploadId> for String {
    fn from(value: UploadId) -> Self {
        value.0
    }
}

#[cfg_attr(test, mutants::skip)]
impl AsRef<str> for UploadId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for UploadId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_decode(value)
    }
}

impl<'de> serde::Deserialize<'de> for UploadId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg_attr(test, mutants::skip)]
impl std::fmt::Display for UploadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl UploadId {
    /// Get a `&str` from the `UploadId`.
    #[cfg_attr(test, mutants::skip)]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Calculate the maximum length of an UploadId without overflow.
    ///
    /// This function computes the largest possible length of an UploadId based on the size of the
    /// alphabet and the maximum value of a u64.
    ///
    /// # Returns
    ///
    /// A usize representing the maximum length of an UploadId, including the check-bit.
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "Constant fn will fail at compile time if out of bounds."
    )]
    #[cfg_attr(test, mutants::skip)] // Skipped becuase mutants to while loop create timeouts
    pub const fn max_id_length() -> usize {
        let largest_usize = {
            let mut largest_so_far = usize::MIN;
            let mut i = 0;
            while i < GEN_ALPHABET.len() {
                let c = GEN_ALPHABET[i];
                if c as usize > largest_so_far {
                    largest_so_far = c as usize;
                }
                i += 1; // Cargo mutants: false positive, can't ignore it due to const fn limitations.
            }
            largest_so_far
        };

        let largest = u64::MAX / largest_usize as u64;

        assert!(
            std::mem::size_of::<usize>() == std::mem::size_of::<u64>(),
            "usize should be equal to u64 in memory on 64-bit systems."
        );

        // Represents the largest possible length of an UploadId without overflow.
        (largest + 1) as usize // We add 1 to account for the check-bit.
    }

    /// Generate a new [`UploadId`] with a specified length.
    ///
    /// # Arguments
    ///
    /// * `N` - The length of the UploadId to generate must be greater than 2 and less than the
    ///   maximum allowable length, which can be found using [`UploadId::max_id_length`].
    ///
    /// # Returns
    ///
    /// A new UploadId instance.
    pub fn generate<const N: usize>() -> Self {
        #[cfg(debug_assertions)]
        {
            assert!(N > 2, "UploadId length must be greater than 2");
            assert!(
                N < Self::max_id_length(),
                "UploadId length must be less than the maximum allowable length."
            );
        }

        let id = {
            let mut rng = rand::thread_rng();
            let distribution = rand::distributions::Uniform::new(0, GEN_ALPHABET.len());

            debug_assert!(!GEN_ALPHABET.contains(&'z'), "z is used as a end stop representation in this loop, and cannot exist in the GEN_ALPHABET.");

            #[allow(
                clippy::arithmetic_side_effects,
                reason = "Size of N checked to be >2."
            )]
            let id_iter = (&mut rng)
                .sample_iter(&distribution)
                .take(N - 1) // To leave space for the check-bit.
                .map(|i| {
                    *GEN_ALPHABET
                        .get(i)
                        .expect("Generated value is guarenteed to be within bounds of alphabet.")
                })
                .chain(std::iter::once('z')); // Push extra item into iterator for next step to work correctly, should not show up in final id.

            // Build a string, ensuring that r + n does not occur, and v + v does not occur.
            // We also must ensure that the final char is not an r, n or v.
            let mut id = String::with_capacity(N);
            for (first, second) in id_iter.tuple_windows() {
                let first = match (first, second) {
                    // In iteration body
                    ('v', 'v') => 'i',
                    ('r', 'n') => 'i',

                    // Final char
                    ('v', 'z') => 'i',
                    ('r', 'z') => 'i',

                    (first, _) => first,
                };
                id.push(first);
            }

            // Calculate the check-bit to append.
            // The conversions between u64 and usize should be no-ops on a 64-bit system, if we
            // ever need to compile for a platform where this is NOT the case the validity of
            // this algorithm will need to be checked.
            debug_assert!(
                std::mem::size_of::<usize>() == std::mem::size_of::<u64>(),
                "usize should be equal to u64 in memory on 64-bit systems."
            );
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "Size of MAX > N > 2, and CHECK_ALPHABET.len() is non-zero."
            )]
            let check_char_idx = id
                .bytes()
                .map(|b| {
                    *CHECK_LOOKUP
                        .get(b as usize)
                        .expect("Generated value is guarenteed to be within bounds.")
                })
                // SAFETY: Sum cannot overflow as N is less than the maximum allowable length.
                .sum::<u64>()
                % CHECK_ALPHABET.len() as u64;
            id.push(
                *CHECK_ALPHABET
                    .get(check_char_idx as usize)
                    .expect("Generated value is guarenteed to be within bounds of check alphabet."),
            );

            debug_assert!(
                !id.contains("rn"),
                "Should not contain rn which may be confused with m."
            );
            debug_assert!(
                !id.contains("vv"),
                "Should not contain vv which may be confused with w."
            );
            debug_assert!(
                !id.contains("z"),
                "Should not contain letter z, indicates bug in refactoring."
            );

            id
        };

        Self(id)
    }

    /// Attempt to decode a given string into an UploadId.
    ///
    /// This function validates the input string, ensuring it contains only valid characters and
    /// has a correct check-bit.
    ///
    /// # Arguments
    ///
    /// * `input` - A string to be decoded into an UploadId.
    ///
    /// # Examples
    /// ```
    /// use server_lib::unique_ids::UploadId;
    /// use std::convert::TryFrom;
    ///
    /// // Generate a new UploadId
    /// let new_id = UploadId::generate::<25>();
    /// println!("Generated UploadId: {}", new_id);
    ///
    /// // Try to decode a valid UploadId string
    /// let valid_id_str = new_id.to_string();
    /// let decoded_id = UploadId::try_from(valid_id_str.clone()).expect("Failed to decode UploadId");
    /// assert_eq!(decoded_id.to_string(), valid_id_str);
    ///
    /// // Try to decode an invalid UploadId string
    /// let invalid_id_str = "invalid_id_string".to_string();
    /// let result = UploadId::try_from(invalid_id_str);
    /// # assert!(result.is_err());
    /// assert_eq!(result.unwrap_err().to_string(), "Invalid UploadId characters");
    /// ```
    ///
    /// # Errors
    ///
    /// This function returns an error if the input string contains invalid characters or has an
    /// incorrect check-bit.
    pub fn try_decode(input: String) -> anyhow::Result<Self> {
        let maybe_valid = input
            .to_lowercase()
            .chars()
            .map(|c| match c {
                'o' | '0' => 'o',
                'i' | 'l' | '1' | '7' => 'i',
                's' | '5' => 's',
                'z' | '2' => 'z',
                'u' | 'v' => 'u',
                'b' | 'g' | '6' | '8' | '9' | 'q' => 'b',
                c => c,
            })
            .collect::<String>()
            // Because we know it's impossible for rm or vv to be in the string, convert them to m and w.
            .replace("rn", "m")
            .replace("vv", "w");

        // Ensure the len is > 1
        anyhow::ensure!(
            maybe_valid.len() > 2,
            "UploadId length must be greater than 2"
        );

        // If any invalid characters are present, return an error.
        anyhow::ensure!(
            maybe_valid.chars().all(|c| CHECK_ALPHABET.contains(&c)),
            "Invalid UploadId characters"
        );

        // Grab the last character as the check-bit.
        let (id, check_char) = maybe_valid.split_at(
            maybe_valid
                .len()
                .checked_sub(1)
                .expect("to be checked above in the ensure"),
        );

        // Calculate the check-bit to append.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "CHECK_ALPHABET.len() is a constant and checked to be > 0."
        )]
        let expt_check_char_idx = id
            .bytes()
            .map(|b| {
                *CHECK_LOOKUP
                    .get(b as usize)
                    .expect("all valid bytes and in bounds")
            })
            // SAFETY: Sum cannot overflow as it has been checked in a debug_assertion above.
            .sum::<u64>()
            % CHECK_ALPHABET.len() as u64;
        let expected_check_char = CHECK_ALPHABET.get(expt_check_char_idx as usize).expect(
            "expt_check_char_idx is guarenteed to be within bounds of check alphabet becuase it has been modded by the length of the alphabet.",
        );

        anyhow::ensure!(
            check_char == expected_check_char.to_string(),
            "Invalid UploadId check-bit",
        );

        Ok(Self(maybe_valid))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;

    #[test]
    fn assert_largest_id_is_fixed() {
        let largest = UploadId::max_id_length();
        assert_eq!(largest, 152_452_430_361_235_964); // Absurdly large number, but it's fixed.

        // Try and generate an id with a very large length, notably this will allocate a string
        // of this size.
        const TEST_SIZE: usize = 1024 * 1024; // 1mb

        let id = UploadId::generate::<TEST_SIZE>();
        assert_eq!(id.as_str().len(), TEST_SIZE);

        // Decode and re-encode the id.
        let id_str = id.to_string();
        let id_decoded = UploadId::try_from(id_str.clone()).expect("Failed to decode UploadId");

        assert_eq!(id_decoded.to_string(), id_str);
    }

    #[test]
    fn test_decode() {
        let test_string = String::from("wcfytxww4opin4jmjjes4ccfd");
        let decoded = UploadId::try_decode(test_string).expect("to be valid id");
        assert_eq!(
            decoded.as_str(),
            "wcfytxww4opin4jmjjes4ccfd",
            "decoded value should be equal to input string"
        );
    }

    #[test]
    fn fuzz_generated_ids() {
        for _ in 0_u64..10_000_u64 {
            let id = UploadId::generate::<25>();
            println!("{}", id);
            assert_eq!(id.as_str().len(), 25);
            assert!(!id.as_str().is_empty());

            // Assert that serializing and deserializing the id doesn't change it.
            let id_str = id.to_string();
            let id = UploadId::try_from(id_str.clone()).expect("Failed to decode UploadId");
            assert_eq!(id.to_string(), id_str);
        }
    }

    #[allow(
        clippy::indexing_slicing,
        unused_must_use,
        reason = "It's a test, bro."
    )]
    #[test]
    fn fuzz_gen_alphabet_strings() {
        let mut rng = rand::thread_rng();
        for _ in 0..100_000_u64 {
            // Generate a random string of characters from 2 to 25 characters long.
            let string = (0..rng.gen_range(2..25))
                .map(|_| GEN_ALPHABET[rng.gen_range(0..GEN_ALPHABET.len())])
                .collect::<String>();

            // Try and decode it - should not panic.
            UploadId::try_decode(string.clone());
        }
    }

    #[allow(unused_must_use, reason = "It's a test, bro.")]
    #[test]
    fn fuzz_random_strings() {
        let mut rng = rand::thread_rng();
        for _ in 0..100_000_u64 {
            // Generate a random string of characters from 2 to 25 characters long.
            let string = (0..rng.gen_range(2..25))
                .map(|_| rng.gen_range(0..=255) as u8 as char)
                .collect::<String>();

            // Try and decode it - should not panic.
            UploadId::try_decode(string.clone());
        }
    }

    #[test]
    fn test_invalid_chars_error() {
        let id = "abc123".to_string();
        let result = UploadId::try_from(id);
        assert!(result.is_err());
        let err = result.expect_err("Should fail due to invalid characters");
        assert_eq!(err.to_string(), "Invalid UploadId characters");
    }

    #[test]
    fn test_invalid_check_bit_error() {
        let invalid_id = String::from("abbsyhbbb4tyxnnmrtjx4crom");
        let result = UploadId::try_from(invalid_id);
        assert!(result.is_err());
        let err = result.expect_err("Should fail due to invalid check-bit");
        assert_eq!(err.to_string(), "Invalid UploadId check-bit");
    }
}
