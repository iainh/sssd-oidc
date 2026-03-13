use std::io::Cursor;

use murmur3::murmur3_32;

/// Map an external ID (SCIM/OIDC UUID) to a local UID within
/// `[range_min, range_min + range_size)`.
///
/// Uses murmur3 (32-bit, seed 0) for deterministic, cross-platform stability.
/// Every server with the same range config produces the same UID for the same ID.
pub fn id_to_uid(external_id: &str, range_min: u32, range_size: u32) -> u32 {
    let hash = murmur3_32(&mut Cursor::new(external_id.as_bytes()), 0)
        .expect("murmur3 hashing cannot fail on a byte slice");
    range_min + (hash % range_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_mapping() {
        let uid1 = id_to_uid("00u1a2b3c4d5e6f7g8h9", 200_000, 200_000);
        let uid2 = id_to_uid("00u1a2b3c4d5e6f7g8h9", 200_000, 200_000);
        assert_eq!(uid1, uid2);
    }

    #[test]
    fn within_range() {
        let uid = id_to_uid("some-uuid-value", 200_000, 200_000);
        assert!(uid >= 200_000);
        assert!(uid < 400_000);
    }

    #[test]
    fn different_ids_differ() {
        let uid_a = id_to_uid("user-a-uuid", 200_000, 200_000);
        let uid_b = id_to_uid("user-b-uuid", 200_000, 200_000);
        // Not guaranteed in general, but extremely likely for these specific inputs.
        assert_ne!(uid_a, uid_b);
    }
}
