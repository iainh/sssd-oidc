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

/// Resolve a UID for `external_id` with linear probing to handle hash collisions.
///
/// 1. If `external_id` already has a cached ID, return it (stable mapping).
/// 2. Otherwise compute the murmur3 candidate and probe linearly until an
///    unused slot is found, then return it.
///
/// `is_taken` receives `(candidate_id, external_id)` and returns:
/// - `Ok(None)` if the slot is free,
/// - `Ok(Some(true))` if the slot is already held by *this* `external_id`,
/// - `Ok(Some(false))` if the slot is held by a *different* `external_id`.
pub fn resolve_id<E>(
    external_id: &str,
    range_min: u32,
    range_size: u32,
    is_taken: impl Fn(u32) -> Result<Option<bool>, E>,
) -> Result<u32, E>
where
    E: From<IdRangeExhausted>,
{
    let base = id_to_uid(external_id, range_min, range_size);
    for offset in 0..range_size {
        let candidate = range_min + (base - range_min + offset) % range_size;
        match is_taken(candidate)? {
            None => return Ok(candidate),       // free slot
            Some(true) => return Ok(candidate), // already ours
            Some(false) => continue,            // collision, probe next
        }
    }
    Err(E::from(IdRangeExhausted))
}

/// Error returned when every slot in the configured ID range is occupied.
#[derive(Debug, Clone, Copy)]
pub struct IdRangeExhausted;

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

    #[test]
    fn resolve_id_probes_on_collision() {
        use std::collections::HashMap;

        // Simulate a taken-slot table: uid → external_id
        let mut taken: HashMap<u32, String> = HashMap::new();

        // First user gets the natural hash slot
        let uid_a: Result<u32, IdRangeExhausted> = resolve_id(
            "user-a",
            100,
            10,
            |candidate| -> Result<_, IdRangeExhausted> {
                match taken.get(&candidate) {
                    None => Ok(None),
                    Some(eid) => Ok(Some(eid == "user-a")),
                }
            },
        );
        let uid_a = uid_a.unwrap();
        taken.insert(uid_a, "user-a".into());

        // Force a collision by pre-occupying user-b's natural slot
        let natural_b = id_to_uid("user-b", 100, 10);
        taken.entry(natural_b).or_insert_with(|| "blocker".into());

        let uid_b: Result<u32, IdRangeExhausted> = resolve_id(
            "user-b",
            100,
            10,
            |candidate| -> Result<_, IdRangeExhausted> {
                match taken.get(&candidate) {
                    None => Ok(None),
                    Some(eid) => Ok(Some(eid == "user-b")),
                }
            },
        );
        let uid_b = uid_b.unwrap();
        assert_ne!(uid_b, natural_b);
        assert!((100..110).contains(&uid_b));
    }

    #[test]
    fn resolve_id_returns_range_exhausted() {
        // Every slot is taken by a different external_id
        let result: Result<u32, IdRangeExhausted> = resolve_id(
            "new-user",
            100,
            3,
            |_candidate| -> Result<_, IdRangeExhausted> {
                Ok(Some(false)) // always taken by someone else
            },
        );
        assert!(result.is_err());
    }
}
