//! Structural RFC 8949 §4.2 pre-check: a dependency-free walk over raw CBOR
//! bytes that rejects indefinite-length items and non-minimal integer
//! headers before any structure decoding, with precise diagnostics.
//!
//! (Map-key ordering and higher-level determinism are enforced by the
//! re-encode-and-compare step in the codec seam; this scanner covers the
//! byte-level rules a `Value` round trip would silently normalize.)

use crate::error::DecodeError;

/// Result of a successful scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan {
    /// The top-level tag number, when the first item is tagged.
    pub top_tag: Option<u64>,
}

/// Maximum nesting depth accepted before failing closed.
const MAX_DEPTH: usize = 32;

/// Scan one complete CBOR item occupying the whole input.
pub fn scan(bytes: &[u8]) -> Result<Scan, DecodeError> {
    let top_tag = match bytes.first() {
        // Major type 6, any additional info.
        Some(b) if b >> 5 == 6 => {
            let (tag, _) = read_head(bytes, 0)?;
            Some(tag)
        }
        Some(_) => None,
        None => return Err(DecodeError::Malformed),
    };
    let end = scan_item(bytes, 0, 0)?;
    if end == bytes.len() {
        Ok(Scan { top_tag })
    } else {
        Err(DecodeError::Malformed)
    }
}

/// Read an item head at `pos`: returns `(argument, next_pos)`, enforcing
/// minimal-length argument encoding.
fn read_head(bytes: &[u8], pos: usize) -> Result<(u64, usize), DecodeError> {
    let initial = *bytes.get(pos).ok_or(DecodeError::Malformed)?;
    let ai = initial & 0x1f;
    match ai {
        0..=23 => Ok((u64::from(ai), pos + 1)),
        24 => {
            let v = *bytes.get(pos + 1).ok_or(DecodeError::Malformed)?;
            // Major type 7 with ai=24 is a simple value, whose only valid
            // (and minimal) range is 32..=255.
            let min = if initial >> 5 == 7 { 32 } else { 24 };
            if v < min {
                return Err(DecodeError::NonMinimalEncoding);
            }
            Ok((u64::from(v), pos + 2))
        }
        25 => {
            let raw = bytes.get(pos + 1..pos + 3).ok_or(DecodeError::Malformed)?;
            let v = u64::from(u16::from_be_bytes(
                raw.try_into().map_err(|_| DecodeError::Malformed)?,
            ));
            // Major type 7 ai=25 is a half-precision float: 2 content bytes,
            // no minimality constraint at this structural level.
            if initial >> 5 != 7 && v < 256 {
                return Err(DecodeError::NonMinimalEncoding);
            }
            Ok((v, pos + 3))
        }
        26 => {
            let raw = bytes.get(pos + 1..pos + 5).ok_or(DecodeError::Malformed)?;
            let v = u64::from(u32::from_be_bytes(
                raw.try_into().map_err(|_| DecodeError::Malformed)?,
            ));
            if initial >> 5 != 7 && v < 65_536 {
                return Err(DecodeError::NonMinimalEncoding);
            }
            Ok((v, pos + 5))
        }
        27 => {
            let raw = bytes.get(pos + 1..pos + 9).ok_or(DecodeError::Malformed)?;
            let v = u64::from_be_bytes(raw.try_into().map_err(|_| DecodeError::Malformed)?);
            if initial >> 5 != 7 && v < 4_294_967_296 {
                return Err(DecodeError::NonMinimalEncoding);
            }
            Ok((v, pos + 9))
        }
        28..=30 => Err(DecodeError::Malformed),
        // 31: indefinite length (or a stray break for major type 7); the
        // caller classifies.
        _ => Err(DecodeError::IndefiniteLength),
    }
}

/// Scan the item starting at `pos`; returns the position just past it.
fn scan_item(bytes: &[u8], pos: usize, depth: usize) -> Result<usize, DecodeError> {
    if depth > MAX_DEPTH {
        return Err(DecodeError::Malformed);
    }
    let initial = *bytes.get(pos).ok_or(DecodeError::Malformed)?;
    let major = initial >> 5;
    if initial & 0x1f == 31 {
        // Indefinite-length bytes/text/array/map are forbidden; a break or
        // an ai=31 on other majors is malformed here.
        return match major {
            2..=5 => Err(DecodeError::IndefiniteLength),
            _ => Err(DecodeError::Malformed),
        };
    }
    let (arg, mut next) = read_head(bytes, pos)?;
    match major {
        // Unsigned / negative integers, simple values and floats: head only.
        0 | 1 | 7 => Ok(next),
        // Byte / text strings: head + content.
        2 | 3 => {
            let len = usize::try_from(arg).map_err(|_| DecodeError::Malformed)?;
            let end = next.checked_add(len).ok_or(DecodeError::Malformed)?;
            if end > bytes.len() {
                return Err(DecodeError::Malformed);
            }
            Ok(end)
        }
        // Arrays: head + n items.
        4 => {
            for _ in 0..arg {
                next = scan_item(bytes, next, depth + 1)?;
            }
            Ok(next)
        }
        // Maps: head + 2n items.
        5 => {
            let pairs = arg.checked_mul(2).ok_or(DecodeError::Malformed)?;
            for _ in 0..pairs {
                next = scan_item(bytes, next, depth + 1)?;
            }
            Ok(next)
        }
        // Tags: head + one item.
        _ => scan_item(bytes, next, depth + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_minimal_encodings() {
        // 0x17 = 23 (immediate), 0x1818 = 24 via one byte.
        assert!(scan(&[0x17]).is_ok());
        assert!(scan(&[0x18, 0x18]).is_ok());
        // Tagged array: D2 82 01 41 AA = 18([1, h'AA'])
        let s = scan(&[0xD2, 0x82, 0x01, 0x41, 0xAA]).unwrap();
        assert_eq!(s.top_tag, Some(18));
    }

    #[test]
    fn rejects_non_minimal_int() {
        // 24 encoded with a two-byte argument.
        assert_eq!(
            scan(&[0x19, 0x00, 0x18]),
            Err(DecodeError::NonMinimalEncoding)
        );
        // 10 encoded with a one-byte argument.
        assert_eq!(scan(&[0x18, 0x0A]), Err(DecodeError::NonMinimalEncoding));
        // bstr length 1 encoded with a one-byte argument.
        assert_eq!(
            scan(&[0x58, 0x01, 0xAA]),
            Err(DecodeError::NonMinimalEncoding)
        );
    }

    #[test]
    fn rejects_indefinite_length() {
        // Indefinite array [_ 1] and indefinite bstr.
        assert_eq!(
            scan(&[0x9F, 0x01, 0xFF]),
            Err(DecodeError::IndefiniteLength)
        );
        assert_eq!(
            scan(&[0x5F, 0x41, 0xAA, 0xFF]),
            Err(DecodeError::IndefiniteLength)
        );
        // Indefinite map.
        assert_eq!(
            scan(&[0xBF, 0x01, 0x02, 0xFF]),
            Err(DecodeError::IndefiniteLength)
        );
    }

    #[test]
    fn rejects_truncation_and_trailing() {
        assert_eq!(scan(&[]), Err(DecodeError::Malformed));
        assert_eq!(scan(&[0x82, 0x01]), Err(DecodeError::Malformed));
        assert_eq!(scan(&[0x01, 0x02]), Err(DecodeError::Malformed));
        // bstr longer than the buffer.
        assert_eq!(scan(&[0x43, 0x01, 0x02]), Err(DecodeError::Malformed));
    }

    #[test]
    fn rejects_deep_nesting() {
        let mut bytes = alloc::vec![0x81u8; 64];
        bytes.push(0x01);
        assert_eq!(scan(&bytes), Err(DecodeError::Malformed));
    }

    #[test]
    fn top_tag_reported() {
        // 96(...) => tag head 0xD8 0x60
        let s = scan(&[0xD8, 0x60, 0x80]).unwrap();
        assert_eq!(s.top_tag, Some(96));
        assert_eq!(scan(&[0x80]).unwrap().top_tag, None);
    }

    #[test]
    fn simple_values_in_invalid_range_rejected() {
        // ai=24 simple value below 32 is non-minimal/invalid.
        assert_eq!(scan(&[0xF8, 0x1F]), Err(DecodeError::NonMinimalEncoding));
        assert!(scan(&[0xF8, 0x20]).is_ok());
        // null / true are structurally fine (type checks happen later).
        assert!(scan(&[0xF6]).is_ok());
    }
}
