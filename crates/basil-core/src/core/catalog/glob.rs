// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Key-glob parsing and matching (design §3.4).
//!
//! A target glob matches a **dotted, lowercase** key segment-by-segment.
//! Wildcards are valid **only** in the last position:
//!
//! - `*` as the whole term is [`KeyGlob::AnyKey`] (the any-wildcard; root-only at
//!   policy-validation time, see [`crate::catalog::loader`]).
//! - `*` as the last segment matches **exactly one** segment (no dot crossing).
//! - `**` as the last segment matches **one or more** trailing segments (a
//!   non-empty tail); it never matches zero segments.
//! - A literal segment matches that segment exactly (case-sensitive, lowercase).
//!
//! Intra-segment wildcards (`web*`) and wildcards that are not in the last
//! position are **fatal syntax errors**: they make accidentally-broad grants too
//! easy to write.

/// A parsed target glob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyGlob {
    /// The whole-term `*`: matches any key (root-only at policy validation, §3.6).
    AnyKey,
    /// A dotted pattern; the final [`GlobSeg`] may be a wildcard.
    Pattern(Vec<GlobSeg>),
}

/// One segment of a [`KeyGlob::Pattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobSeg {
    /// A literal, exact-match segment (lowercase).
    Literal(String),
    /// `*` in the last position: matches exactly one segment.
    Star,
    /// `**` in the last position: matches one or more trailing segments.
    DoubleStar,
}

/// Why a glob term failed to parse (§3.4). All variants are fatal load errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlobError {
    /// An empty term, or an empty segment (e.g. `web..tls` or a leading/trailing dot).
    #[error("empty glob term or segment in `{0}`")]
    Empty(String),

    /// A `*` or `**` wildcard that is not the last segment.
    #[error("wildcard `{wildcard}` is only valid as the last segment, in `{term}`")]
    WildcardNotLast {
        /// The whole offending term.
        term: String,
        /// The wildcard segment that appeared too early.
        wildcard: String,
    },

    /// An intra-segment wildcard such as `web*` or `*key` (never a literal).
    #[error("intra-segment wildcard in segment `{segment}` of `{term}`")]
    IntraSegment {
        /// The whole offending term.
        term: String,
        /// The segment that mixed a wildcard with literal characters.
        segment: String,
    },
}

impl KeyGlob {
    /// Parse a target term into a [`KeyGlob`].
    ///
    /// `*` as the whole term is [`KeyGlob::AnyKey`]; otherwise the term is split
    /// on `.` and each segment is classified. See the module docs and §3.4.
    pub fn parse(s: &str) -> Result<Self, GlobError> {
        if s == "*" {
            return Ok(Self::AnyKey);
        }
        if s.is_empty() {
            return Err(GlobError::Empty(s.to_string()));
        }

        let raw: Vec<&str> = s.split('.').collect();
        let last = raw.len() - 1;
        let mut segs = Vec::with_capacity(raw.len());

        for (i, seg) in raw.into_iter().enumerate() {
            if seg.is_empty() {
                return Err(GlobError::Empty(s.to_string()));
            }
            let is_last = i == last;
            match seg {
                "*" => {
                    if !is_last {
                        return Err(GlobError::WildcardNotLast {
                            term: s.to_string(),
                            wildcard: "*".to_string(),
                        });
                    }
                    segs.push(GlobSeg::Star);
                }
                "**" => {
                    if !is_last {
                        return Err(GlobError::WildcardNotLast {
                            term: s.to_string(),
                            wildcard: "**".to_string(),
                        });
                    }
                    segs.push(GlobSeg::DoubleStar);
                }
                literal => {
                    // Any `*` mixed with literal characters is an intra-segment
                    // wildcard (`web*`, `*key`, `we*b`): a fatal syntax error.
                    if literal.contains('*') {
                        return Err(GlobError::IntraSegment {
                            term: s.to_string(),
                            segment: literal.to_string(),
                        });
                    }
                    segs.push(GlobSeg::Literal(literal.to_string()));
                }
            }
        }

        Ok(Self::Pattern(segs))
    }

    /// The canonical source spelling of this glob (the inverse of [`KeyGlob::parse`]),
    /// e.g. `grafana.**` or `*`. Used to render the matched target in a policy
    /// `explain`. Round-trips: `KeyGlob::parse(&g.source()).unwrap() == g`.
    #[must_use]
    pub fn source(&self) -> String {
        match self {
            Self::AnyKey => "*".to_string(),
            Self::Pattern(segs) => segs
                .iter()
                .map(|seg| match seg {
                    GlobSeg::Literal(s) => s.as_str(),
                    GlobSeg::Star => "*",
                    GlobSeg::DoubleStar => "**",
                })
                .collect::<Vec<_>>()
                .join("."),
        }
    }

    /// Does this glob match `dotted_key`? See §3.4.
    #[must_use]
    pub fn matches(&self, dotted_key: &str) -> bool {
        let key: Vec<&str> = dotted_key.split('.').collect();
        match self {
            Self::AnyKey => true,
            Self::Pattern(segs) => Self::pattern_matches(segs, &key),
        }
    }

    fn pattern_matches(segs: &[GlobSeg], key: &[&str]) -> bool {
        // A wildcard, when present, is always the final segment. So all but the
        // last segment must be literals matching positionally, and the last
        // segment determines how many trailing key segments are consumed.
        let Some((last_seg, lead)) = segs.split_last() else {
            // An empty pattern matches nothing (and parse never yields one).
            return false;
        };

        if key.len() < lead.len() {
            return false;
        }
        for (seg, k) in lead.iter().zip(key) {
            // Leading segments are guaranteed literal by `parse`.
            match seg {
                GlobSeg::Literal(lit) => {
                    if lit != k {
                        return false;
                    }
                }
                GlobSeg::Star | GlobSeg::DoubleStar => return false,
            }
        }

        // `key.len() >= lead.len()` is guaranteed by the early return above, so
        // the split is always in bounds; an unmatchable empty tail otherwise.
        let tail = key.get(lead.len()..).unwrap_or(&[]);
        match last_seg {
            // Exactly one remaining segment.
            GlobSeg::Star => tail.len() == 1,
            // One or more remaining segments (never zero).
            GlobSeg::DoubleStar => !tail.is_empty(),
            // Exactly one remaining segment, equal to the literal.
            GlobSeg::Literal(lit) => tail.len() == 1 && tail.first() == Some(&lit.as_str()),
        }
    }

    /// Whether this glob is the whole-term `*` (subject to the root-only rule, §3.6).
    #[must_use]
    pub const fn is_any_key(&self) -> bool {
        matches!(self, Self::AnyKey)
    }

    /// Whether this glob matches **every** catalog key.
    ///
    /// True for the whole-term `*` ([`KeyGlob::AnyKey`]) and for a bare `**`
    /// (`Pattern([DoubleStar])`, which matches any non-empty key). The
    /// break-glass any-target gate keys on this, not on [`KeyGlob::is_any_key`],
    /// so `**` cannot be used to sidestep the `*` guardrail while granting the
    /// same reach.
    #[must_use]
    pub fn matches_all(&self) -> bool {
        match self {
            Self::AnyKey => true,
            Self::Pattern(segs) => matches!(segs.as_slice(), [GlobSeg::DoubleStar]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_round_trips_through_parse() {
        for s in [
            "*",
            "web.tls.signing_key",
            "web.tls.*",
            "web.**",
            "grafana.admin_password",
        ] {
            let g = KeyGlob::parse(s).expect("parses");
            assert_eq!(g.source(), s, "source spelling must round-trip");
            assert_eq!(KeyGlob::parse(&g.source()).expect("reparse"), g);
        }
    }

    // ---- The §3.4 truth table (load-bearing) --------------------------------

    #[test]
    fn spec_table_against_web_tls_signing_key() {
        let key = "web.tls.signing_key";
        let cases: &[(&str, bool)] = &[
            ("web.tls.signing_key", true), // exact
            ("web.tls.*", true),           // `*` = signing_key (one segment)
            ("web.*", false),              // `*` = tls, leaves signing_key unmatched
            ("web.**", true),              // `**` = tail tls.signing_key
            ("web", false),                // shorter than key, no `**`
        ];
        for (glob, expect) in cases {
            let g = KeyGlob::parse(glob).expect("table globs parse");
            assert_eq!(g.matches(key), *expect, "glob `{glob}` vs `{key}`");
        }
        // `web*` is a fatal load error, not a match/non-match.
        assert!(matches!(
            KeyGlob::parse("web*"),
            Err(GlobError::IntraSegment { .. })
        ));
    }

    #[test]
    fn star_matches_exactly_one_segment_no_dot_crossing() {
        let g = KeyGlob::parse("web.tls.*").unwrap();
        assert!(g.matches("web.tls.signing_key"));
        assert!(!g.matches("web.tls.a.b")); // `*` does not cross a dot
        assert!(!g.matches("web.tls")); // `*` needs exactly one trailing segment
    }

    #[test]
    fn doublestar_is_one_or_more_not_zero() {
        let g = KeyGlob::parse("web.**").unwrap();
        assert!(g.matches("web.tls")); // one trailing segment
        assert!(g.matches("web.tls.signing_key")); // many trailing segments
        assert!(!g.matches("web")); // ** does NOT match zero (bare prefix)
        assert!(!g.matches("other.tls")); // literal prefix must still match
    }

    #[test]
    fn any_key_matches_everything() {
        let g = KeyGlob::parse("*").unwrap();
        assert!(g.is_any_key());
        assert!(g.matches("anything"));
        assert!(g.matches("a.b.c.d"));
    }

    #[test]
    fn literal_only_is_exact() {
        let g = KeyGlob::parse("nats.account").unwrap();
        assert!(g.matches("nats.account"));
        assert!(!g.matches("nats.account.sub"));
        assert!(!g.matches("nats"));
        assert!(!g.matches("NATS.account")); // case-sensitive, lowercase
    }

    // ---- Parse error cases --------------------------------------------------

    #[test]
    fn intra_segment_wildcard_is_fatal() {
        assert!(matches!(
            KeyGlob::parse("web*"),
            Err(GlobError::IntraSegment { .. })
        ));
        assert!(matches!(
            KeyGlob::parse("web.tls*"),
            Err(GlobError::IntraSegment { .. })
        ));
        assert!(matches!(
            KeyGlob::parse("*key"),
            Err(GlobError::IntraSegment { .. })
        ));
        assert!(matches!(
            KeyGlob::parse("web.*key"),
            Err(GlobError::IntraSegment { .. })
        ));
    }

    #[test]
    fn wildcard_not_in_last_position_is_fatal() {
        // `user.*.ssh.authorized_keys`: glob not last (§3.4).
        assert!(matches!(
            KeyGlob::parse("user.*.ssh.authorized_keys"),
            Err(GlobError::WildcardNotLast { .. })
        ));
        assert!(matches!(
            KeyGlob::parse("web.**.x"),
            Err(GlobError::WildcardNotLast { .. })
        ));
        assert!(matches!(
            KeyGlob::parse("*.tls"),
            Err(GlobError::WildcardNotLast { .. })
        ));
    }

    #[test]
    fn empty_segments_are_fatal() {
        assert!(matches!(KeyGlob::parse(""), Err(GlobError::Empty(_))));
        assert!(matches!(
            KeyGlob::parse("web..tls"),
            Err(GlobError::Empty(_))
        ));
        assert!(matches!(KeyGlob::parse(".web"), Err(GlobError::Empty(_))));
        assert!(matches!(KeyGlob::parse("web."), Err(GlobError::Empty(_))));
    }

    #[test]
    fn doublestar_alone_matches_one_or_more() {
        let g = KeyGlob::parse("**").unwrap();
        assert!(matches!(g, KeyGlob::Pattern(_)));
        assert!(g.matches("a"));
        assert!(g.matches("a.b"));
        // a single-segment key still has at least one segment, so it matches.
    }

    #[test]
    fn matches_all_covers_star_and_bare_doublestar() {
        // Both spellings grant the entire catalog and must trip the break-glass
        // any-target gate; anything narrower must not.
        assert!(KeyGlob::parse("*").unwrap().matches_all());
        assert!(KeyGlob::parse("**").unwrap().matches_all());
        for narrower in ["web.**", "web.*", "web.tls.signing_key"] {
            assert!(
                !KeyGlob::parse(narrower).unwrap().matches_all(),
                "`{narrower}` must not count as match-everything"
            );
        }
    }
}
