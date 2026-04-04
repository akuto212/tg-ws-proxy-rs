use std::collections::HashMap;

/// DC override mapping (e.g., DC203 → DC2 for WS domains).
pub fn dc_override(dc: u8) -> u8 {
    match dc {
        203 => 2,
        other => other,
    }
}

/// Default fallback IPs for each DC (used when WS fails and DC is not in dc_redirects).
pub fn dc_default_ips() -> HashMap<u8, &'static str> {
    HashMap::from([
        (1, "149.154.175.50"),
        (2, "149.154.167.51"),
        (3, "149.154.175.100"),
        (4, "149.154.167.91"),
        (5, "149.154.171.5"),
        (203, "91.105.192.100"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dc_override_203_to_2() {
        assert_eq!(dc_override(203), 2);
    }

    #[test]
    fn test_dc_override_passthrough() {
        for dc in [1, 2, 3, 4, 5] {
            assert_eq!(dc_override(dc), dc);
        }
    }

    #[test]
    fn test_dc_default_ips_has_all_dcs() {
        let ips = dc_default_ips();
        for dc in [1, 2, 3, 4, 5, 203] {
            assert!(ips.contains_key(&dc), "Missing DC {dc}");
        }
    }
}
