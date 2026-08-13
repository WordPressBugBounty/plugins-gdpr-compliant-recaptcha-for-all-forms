<?php
/**
 * Pure, WordPress-independent value extraction for the value-based spam patterns
 * (BACKLOG "Wertbasierte Spam-Pattern über alle Formulare"): both the wildcard
 * value patterns ({"*":"value"}) and the auto-echo lock.
 *
 * This class knows nothing about WordPress (no options, no $wpdb, no transients,
 * no home_url()) — the WP glue (reading the pattern option, the transient store,
 * the site's own domain) lives in the thin integration layer (Echo_Store and
 * Stamp). That keeps every non-trivial invariant unit-testable in isolation, see
 * tests/unit/EchoValuesTest.php.
 *
 * Three consumers:
 * - Wildcard value matching: collect_user_values()/matches_wildcard_values()/
 *   wildcard_values_from_lines() — an admin-configured {"*":"value"} line matches
 *   when ANY user-content field (any depth) equals that value (trim + lowercase),
 *   or carries it as an embedded email address / URL domain. A line written with a
 *   leading "@" ({"*":"@spam.tld"}) is instead a SENDER-DOMAIN blocklist entry and
 *   takes part only in that one comparison — see matches_wildcard_values().
 * - Auto-echo lock: build_echo_set() extracts the "core values" of a submission
 *   (sender email, payload domain, phone, long-text hash), returns them as SHA-256
 *   hashes only (GDPR: never store the plaintext of a personally-identifiable
 *   value), and Echo_Store persists/looks them up with a TTL.
 * - Login exemption of the wildcard blocklist: blocked_emails() + all_emails_exempt() —
 *   which addresses of a submission the ADDRESS-BASED blocklist comparison hit, and
 *   whether every one of them belongs to a registered account. Uses the same
 *   split_wildcard_values()/email_is_blocked() rule as matches_wildcard_values(), never a
 *   second formulation of it. Glue: Stamp::is_exempt_login_submission().
 *
 * HARD security invariants (see class docblocks below and the BACKLOG entry):
 * 1. Extraction runs ONLY over user-content fields: technical keys are skipped
 *    (underscore-prefixed, e.g. _wpcf7*, and the referrer/page-URL field-name
 *    blacklist) — otherwise the site's own referrer/page URL in whole_request_data
 *    would seed an echo/wildcard value for the site's own domain (self-DoS).
 * 2. The site's own registrable domain is NEVER emitted as an echo value — the
 *    caller passes its own domain(s) as the $own_domains exclude list, and URL
 *    extraction drops any URL resolving to them. This is the SECOND, independent
 *    defense line to invariant 1 (either alone must already prevent the self-block).
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Stateless value extraction / normalization for the value-based spam patterns.
 */
final class Echo_Values {

	/**
	 * Multi-part public suffixes (eTLD) where the registrable domain (eTLD+1) is
	 * the last THREE labels, not the last two. Deliberately a curated, conservative
	 * built-in list — NOT the full Public Suffix List (no external dependency, no
	 * bundled ~10k-entry file to keep in sync). Being incomplete is safe: a missing
	 * multi-part suffix only means we echo one label too FEW (e.g. "co.uk" instead
	 * of "spam.co.uk"), which never blocks more than intended — at worst it fails to
	 * block. Extend as real misses show up in field data.
	 *
	 * @var string[]
	 */
	const MULTI_PART_SUFFIXES = array(
		'co.uk',
		'org.uk',
		'gov.uk',
		'ac.uk',
		'net.uk',
		'sch.uk',
		'ltd.uk',
		'plc.uk',
		'me.uk',
		'com.au',
		'net.au',
		'org.au',
		'edu.au',
		'gov.au',
		'com.br',
		'com.mx',
		'com.ar',
		'co.jp',
		'ne.jp',
		'or.jp',
		'co.nz',
		'co.za',
		'co.in',
		'com.cn',
		'com.tr',
		'com.sg',
		'com.hk',
		'com.tw',
	);

	/**
	 * Hosts where the PATH (not just the domain) carries the sender's identity:
	 * messenger deep-links and URL shorteners. For these, the echo/block value is
	 * "host/first-path-segment" (e.g. "t.me/spammer123") rather than the bare host —
	 * otherwise blocking one Telegram spammer's link would block every t.me link on
	 * the site. Curated const, extend as needed.
	 *
	 * @var string[]
	 */
	const PATH_IDENTITY_HOSTS = array(
		't.me',
		'wa.me',
		'telegram.me',
		'bit.ly',
		'tinyurl.com',
		'goo.gl',
		'is.gd',
		'cutt.ly',
		'rb.gy',
		'linktr.ee',
	);

	/**
	 * Exact (case-insensitive) field names that are technical, not user content,
	 * and must never be extracted from — they typically carry the site's own
	 * referrer/page URL. This is in addition to the underscore-prefix rule in
	 * is_technical_key() (covers _wpcf7_container_post, _wpcf7_unit_tag,
	 * _wp_http_referer, …). Kept to the exact blacklist from the BACKLOG entry.
	 *
	 * @var string[]
	 */
	const TECHNICAL_FIELD_NAMES = array( 'referer', 'referrer', 'page_url', 'url' );

	/**
	 * Minimum number of NORMALIZED characters (letters/digits, whitespace and
	 * punctuation removed) a text value must have before its hash is echoed. Below
	 * this, short standard values ("yes", first names, "Berlin") would collide and
	 * cause false positives, so they are ignored. Deliberately exact, not fuzzy.
	 */
	const TEXT_HASH_MIN_LENGTH = 40;

	/** Minimum digit count for a value to be treated as a phone number. */
	const PHONE_MIN_DIGITS = 7;

	/** Recursion depth cap for the field walk (defensive; forms rarely nest deep). */
	const MAX_DEPTH = 6;

	/**
	 * SHA-256 of a value (lower-case hex, 64 chars). All echo values are stored and
	 * compared ONLY as this hash (GDPR: no plaintext of an email/phone/text).
	 *
	 * @param string $value Input.
	 * @return string 64-char lower-case hex digest.
	 */
	public static function hash_value( $value ) {
		return hash( 'sha256', (string) $value, false );
	}

	/**
	 * Whether a field key is technical (not user content) and must be skipped:
	 * underscore-prefixed (e.g. _wpcf7*) or in TECHNICAL_FIELD_NAMES.
	 *
	 * @param string $key Field key.
	 * @return bool
	 */
	public static function is_technical_key( $key ) {
		$key = (string) $key;
		if ( '' === $key ) {
			return false;
		}
		if ( '_' === $key[0] ) {
			return true;
		}
		return in_array( strtolower( $key ), self::TECHNICAL_FIELD_NAMES, true );
	}

	/**
	 * Collect the raw string leaves of the user-content fields of a submission,
	 * recursively, skipping technical keys (see is_technical_key()) at every level.
	 * Non-array/non-scalar values are ignored; empty strings dropped.
	 *
	 * @param mixed $fields Field map (request-derived, so not guaranteed an array).
	 * @param int   $depth  Current recursion depth (internal).
	 * @return string[] User-content string values.
	 */
	public static function collect_content_strings( $fields, $depth = 0 ) {
		$out = array();
		if ( $depth > self::MAX_DEPTH || ! is_array( $fields ) ) {
			return $out;
		}
		foreach ( $fields as $key => $value ) {
			if ( self::is_technical_key( (string) $key ) ) {
				continue;
			}
			if ( is_array( $value ) ) {
				$out = array_merge( $out, self::collect_content_strings( $value, $depth + 1 ) );
			} elseif ( is_scalar( $value ) ) {
				$string = (string) $value;
				if ( '' !== $string ) {
					$out[] = $string;
				}
			}
		}
		return $out;
	}

	/**
	 * Normalize a value for wildcard comparison: trim + lowercase, exactly as the
	 * BACKLOG entry specifies.
	 *
	 * @param string $value Raw value.
	 * @return string Normalized value.
	 */
	public static function normalize_wildcard( $value ) {
		return strtolower( trim( (string) $value ) );
	}

	/**
	 * Collect the normalized (trim + lowercase) user-content string values of a
	 * submission, for wildcard-value comparison.
	 *
	 * @param mixed $fields Field map.
	 * @return string[]
	 */
	public static function collect_user_values( $fields ) {
		$out = array();
		foreach ( self::collect_content_strings( $fields ) as $string ) {
			$out[] = self::normalize_wildcard( $string );
		}
		return $out;
	}

	/**
	 * LEGACY JSON form of the blocklist, read from raw POW_PARAMETER_PATTERN lines:
	 * a line is a wildcard line iff it JSON-decodes to a single-entry object
	 * {"*":"value"} with a string value. Non-wildcard pattern lines are ignored.
	 *
	 * This is the format the value-based blocklist used to be stored in, mixed
	 * into the pattern option (BACKLOG "Blocklisten-Werte aus
	 * POW_PARAMETER_PATTERN herausloesen", PLAN-BLOCKLIST-TRENNUNG.md). It now
	 * exists ONLY so the one-time migration into POW_BLOCKED_VALUES
	 * (Blocked_Values_Migration, AP5) has something to read the old lines with —
	 * new blocklist entries are plain-text lines read via
	 * values_from_plaintext_lines() instead. Kept unchanged for that purpose.
	 *
	 * @param string[] $lines Raw pattern lines.
	 * @return string[] Unique, normalized, non-empty wildcard values.
	 */
	public static function wildcard_values_from_lines( $lines ) {
		$values = array();
		foreach ( (array) $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line ) {
				continue;
			}
			$decoded = json_decode( $line, true );
			if ( ! is_array( $decoded ) || 1 !== count( $decoded ) || ! array_key_exists( '*', $decoded ) || ! is_string( $decoded['*'] ) ) {
				continue;
			}
			$value = self::normalize_wildcard( $decoded['*'] );
			if ( '' !== $value ) {
				$values[] = $value;
			}
		}
		return array_values( array_unique( $values ) );
	}

	/**
	 * The CURRENT, plain-text form of the blocklist: one value per line, no JSON
	 * envelope (PLAN-BLOCKLIST-TRENNUNG.md AP2). This is — and, once the migration
	 * and the settings page land (AP3/AP5), will be THE — source of
	 * POW_BLOCKED_VALUES, the standalone blocklist option that replaces the
	 * {"*":"value"}/{"*":"@domain"} lines formerly mixed into
	 * POW_PARAMETER_PATTERN. wildcard_values_from_lines() above is the JSON
	 * twin: it stays only to read the OLD form during the one-time migration.
	 *
	 * Each line is normalized via normalize_wildcard() (trim + lowercase — the
	 * existing rule, not reimplemented here), empty lines are dropped, and the
	 * result is deduplicated. This function does NOT decide which of the four
	 * match forms (exact value, email, link domain, "@sender-domain") a value
	 * plays — that stays entirely in matches_wildcard_values()/
	 * split_wildcard_values(), unchanged. It only produces the normalized value
	 * list, in exactly the shape wildcard_values_from_lines() also returns, so
	 * both are interchangeable as the $wildcard_values argument of
	 * matches_wildcard_values().
	 *
	 * @param string[] $lines Raw blocklist lines (plain text, one value per line).
	 * @return string[] Unique, normalized, non-empty values.
	 */
	public static function values_from_plaintext_lines( $lines ) {
		$values = array();
		foreach ( (array) $lines as $line ) {
			$value = self::normalize_wildcard( $line );
			if ( '' !== $value ) {
				$values[] = $value;
			}
		}
		return array_values( array_unique( $values ) );
	}

	/**
	 * Whether any user-content field of $fields matches one of the already-normalized
	 * $wildcard_values. Four comparisons per field value, so a one-click block stays
	 * effective when the blocked value is EMBEDDED in message text rather than being
	 * the whole field ("Block this domain" would otherwise be near-useless — spam
	 * links live inside the message body, not in a field equal to "spam.com"):
	 * 1. whole-value equality (trim + lowercase — the literal spec rule),
	 * 2. every email address extracted from the value,
	 * 3. the registrable domain (or path identity) of every URL extracted from the
	 *    value — with $own_domains excluded, so even a hand-typed wildcard line for
	 *    the site's own domain can never match a legitimate submission that merely
	 *    contains an internal link (same defense line as in build_echo_set()),
	 * 4. the SENDER DOMAIN (the part behind the last "@") of every extracted email
	 *    address, against the wildcard values written with a leading "@"
	 *    ({"*":"@mailinator.com"}) — the blocklist form for throwaway domains whose
	 *    local parts rotate, so blocking single addresses never catches up.
	 *
	 * The two forms are disjoint by construction: a value with a leading "@" takes
	 * part ONLY in comparison 4, never in 1–3. That is deliberate — a field whose
	 * entire content is "@gmail.com" is not a sender address, and a bare domain line
	 * keeps its existing meaning (URL domain), which is what the "Block this domain"
	 * button has been writing all along; widening it silently would change behavior
	 * on running installations.
	 *
	 * Sender-domain entries are subdomain-tolerant WITHOUT eTLD normalization: the
	 * sender domain hits when it equals the entry or ends in "." . entry. The dot is
	 * load-bearing — "notgmail.com" must never be caught by a "@gmail.com" entry.
	 * Matching runs against the ENTRY itself, not its registrable domain, so a listed
	 * "@sub.example.org" hits exactly that subdomain.
	 *
	 * An entry whose domain is not usable as a blocklist rule (is_blockable_sender_domain()
	 * says no — own domain, bare public suffix, IP, dot-less word) does NOT become inert:
	 * it falls back to comparison 1, which is exactly what such a line did before this
	 * feature existed. Dropping it instead would silently disarm a working hand-typed
	 * block on an installation that never asked for the new behavior.
	 *
	 * @param mixed    $fields          Field map.
	 * @param string[] $wildcard_values Normalized wildcard values.
	 * @param string[] $own_domains     Registrable domains of the site itself,
	 *                                  excluded from URL-domain extraction and from
	 *                                  the sender-domain blocklist.
	 * @return bool
	 */
	public static function matches_wildcard_values( $fields, $wildcard_values, $own_domains = array() ) {
		if ( empty( $wildcard_values ) ) {
			return false;
		}
		list( $set, $sender_domains ) = self::split_wildcard_values( $wildcard_values, $own_domains );
		foreach ( self::collect_content_strings( $fields ) as $string ) {
			if ( isset( $set[ self::normalize_wildcard( $string ) ] ) ) {
				return true;
			}
			foreach ( self::extract_emails( $string ) as $email ) {
				if ( self::email_is_blocked( $email, $set, $sender_domains ) ) {
					return true;
				}
			}
			foreach ( self::extract_urls( $string ) as $url ) {
				$domain = self::registrable_domain( $url, $own_domains );
				if ( null !== $domain && isset( $set[ $domain ] ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Split a set of already-normalized wildcard values into the two comparison sets the
	 * blocklist rule is built from:
	 * - the EXACT values: every entry without a leading "@", PLUS every "@…" entry that
	 *   is not usable as a sender-domain rule and therefore falls back to its historical
	 *   whole-value meaning (see below),
	 * - the SENDER DOMAINS: the domain part of every usable "@domain" entry, "@" stripped.
	 *
	 * THE ONE implementation of that split, deliberately shared rather than repeated:
	 * matches_wildcard_values() ("does anything match at all?") and blocked_emails()
	 * ("which addresses did the matching?") must be incapable of disagreeing. A second,
	 * "equivalent" copy of a matching rule is the construction error already named in the
	 * head docblock of Pattern_Matcher — and here it would be worse than cosmetic: the
	 * login exemption (Stamp::is_exempt_login_submission()) decides whether a block is
	 * lifted from the SAME comparison, so a copy that drifted would lift blocks that were
	 * never analysed.
	 *
	 * @param string[] $wildcard_values Normalized wildcard values.
	 * @param string[] $own_domains     Registrable domains of the site itself.
	 * @return array{0:array<string,int>,1:string[]} Exact-value lookup set (array_flip'ed,
	 *                                               isset()-ready) and blocked sender domains.
	 */
	private static function split_wildcard_values( $wildcard_values, $own_domains ) {
		$exact_values   = array();
		$sender_domains = array();
		foreach ( (array) $wildcard_values as $value ) {
			$value = (string) $value;
			if ( '' === $value || '@' !== $value[0] ) {
				$exact_values[] = $value;
				continue;
			}
			$domain = substr( $value, 1 );
			if ( self::is_blockable_sender_domain( $domain, $own_domains ) ) {
				$sender_domains[] = $domain;
				continue;
			}
			// Not usable as a sender-domain rule. Keep the line's HISTORICAL meaning
			// (plain exact value) instead of dropping it: a hand-typed pre-existing
			// line like {"*":"@somehandle"} blocked a field equal to that string
			// before this feature existed, and silently turning a working block into
			// a no-op would remove protection on a running installation without
			// telling anyone.
			$exact_values[] = $value;
		}
		return array( array_flip( $exact_values ), $sender_domains );
	}

	/**
	 * Whether an extracted email address is hit by an ADDRESS-BASED comparison of the
	 * blocklist: exact address equality against an entry written without the "@" prefix
	 * (comparison 2 of matches_wildcard_values()), or a sender-domain hit against an
	 * "@" entry (comparison 4). Whole-value equality (1) and URL domains (3) are NOT
	 * address-based and deliberately have no part here — see blocked_emails().
	 *
	 * Note that an "@…" entry which fell back to the exact set can never be hit by this
	 * path: extract_emails() requires a non-empty local part, so an extracted address
	 * never starts with "@".
	 *
	 * @param string            $email          Lower-cased address from extract_emails().
	 * @param array<string,int> $exact_set      Exact-value lookup set from split_wildcard_values().
	 * @param string[]          $sender_domains Blocked sender domains from split_wildcard_values().
	 * @return bool
	 */
	private static function email_is_blocked( $email, $exact_set, $sender_domains ) {
		if ( isset( $exact_set[ $email ] ) ) {
			return true;
		}
		return self::email_has_blocked_sender_domain( $email, $sender_domains );
	}

	/**
	 * The set B of the LOGIN EXEMPTION (Stamp::is_exempt_login_submission()): the unique,
	 * normalized email addresses of a submission that are hit by an ADDRESS-BASED
	 * blocklist comparison — i.e. exactly those addresses that CAUSED, or would cause, the
	 * wildcard classification through their identity as an address.
	 *
	 * The exemption asks "do the addresses that triggered this block belong to registered
	 * users?", and this function answers the first half of that question. It runs through
	 * split_wildcard_values()/email_is_blocked(), i.e. through the very same rule
	 * matches_wildcard_values() uses — never a second formulation of it.
	 *
	 * WHY THE SET, AND NOT "does the submission contain a registered address?" — the
	 * measured attack this replaced: the former contains_exempt_email() looked at ALL
	 * content fields for ANY registered address. It was therefore enough to append one
	 * known registered address (typically the publicly findable admin address) to a login
	 * POST to buy the exemption for an arbitrary blocked identity:
	 * `log=stranger@blocked.test` + `freeride=chef@site.example` came through, as did the
	 * same address parked in `pwd` or `redirect_to`. The exemption was bought, not earned.
	 * With the set, the extra address is simply not in B (it is not blocked), so it buys
	 * nothing; and if the attacker knows a registered address AT the blocked domain, B
	 * contains BOTH and the foreign one is not registered — see all_emails_exempt(), whose
	 * ALL-quantor is what closes that case.
	 *
	 * An EMPTY result means the wildcard hit came from a non-address comparison
	 * (whole-value equality or an URL domain). The exemption then does not apply at all:
	 * fails CLOSED, as everywhere in this class.
	 *
	 * @param mixed    $fields          Field map (technical keys skipped, invariant 1).
	 * @param string[] $wildcard_values Normalized wildcard values.
	 * @param string[] $own_domains     Registrable domains of the site itself.
	 * @return string[] Unique, lower-cased addresses; empty when no address-based comparison hit.
	 */
	public static function blocked_emails( $fields, $wildcard_values, $own_domains = array() ) {
		if ( empty( $wildcard_values ) ) {
			return array();
		}
		list( $set, $sender_domains ) = self::split_wildcard_values( $wildcard_values, $own_domains );
		$blocked                      = array();
		foreach ( self::collect_content_strings( $fields ) as $string ) {
			foreach ( self::extract_emails( $string ) as $email ) {
				if ( self::email_is_blocked( $email, $set, $sender_domains ) ) {
					$blocked[ $email ] = true;
				}
			}
		}
		return array_keys( $blocked );
	}

	/**
	 * The second half of the login exemption: whether $emails is NON-EMPTY and EVERY
	 * address in it hashes into $exempt_hashes (the registered users' addresses,
	 * Echo_Store::user_email_hashes()).
	 *
	 * Both quantifiers are load-bearing and neither may be relaxed:
	 * - NON-EMPTY: an empty B means no address caused the block, so there is nothing an
	 *   account could vouch for — no exemption (fail closed).
	 * - EVERY: one registered address among several blocked ones must not free the rest.
	 *   An attacker who knows a registered address at the blocked domain would otherwise
	 *   send it alongside his own and be waved through with it.
	 *
	 * Normalization is trim + lowercase, i.e. exactly what extract_emails() and
	 * hash_emails() apply, so a hash computed here is bit-identical to the one the exempt
	 * set was built from. If the two ever drifted apart, no address would ever match and
	 * the exemption would be silently dead code (green tests, locked-out operator);
	 * tests/unit/EchoValuesTest.php pins both paths against each other.
	 *
	 * INHERITED LIMIT, measured: an address whose local part carries characters
	 * extract_emails() does not accept (anything outside its ASCII class, e.g. an umlaut)
	 * is extracted only from its ASCII tail, so its hash cannot equal the hash of the full
	 * address in the exempt set — such an account would not be exempt. That is the
	 * extractor's pre-existing character set, shared with the echo lock, not a rule of its
	 * own; it fails CLOSED (no exemption), never open.
	 *
	 * GDPR: only hashes are compared, never a plaintext address (same rule as everywhere
	 * else in this class).
	 *
	 * @param string[] $emails        Addresses to check (typically blocked_emails()).
	 * @param string[] $exempt_hashes SHA-256 hashes (lower-case hex) of exempt addresses.
	 * @return bool
	 */
	public static function all_emails_exempt( $emails, $exempt_hashes ) {
		$emails = (array) $emails;
		if ( empty( $emails ) || empty( $exempt_hashes ) ) {
			return false;
		}
		$set = array_flip( (array) $exempt_hashes );
		foreach ( $emails as $email ) {
			$normalized = strtolower( trim( (string) $email ) );
			if ( '' === $normalized || ! isset( $set[ self::hash_value( $normalized ) ] ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether $domain may be used as a sender-domain blocklist entry ("@domain"). The
	 * ONE rule shared by all three sites that decide about such an entry: this matcher,
	 * the button in Message_Page::render_message(), and Message_Page::block_value_callback().
	 * Sharing the function rather than repeating an equivalent condition is deliberate —
	 * a site that judged differently would either offer a button whose result can never
	 * match, or store a line the matcher refuses.
	 *
	 * Three ways to be unusable:
	 * 1. registrable_domain() returns null — the site's OWN domain (self-DoS guard, same
	 *    defense line as the URL-domain comparison), an IP literal, or a dot-less word.
	 * 2. The domain IS a public suffix itself ("co.uk"). registrable_domain() cannot
	 *    reject this on its own: it only consults MULTI_PART_SUFFIXES from three labels
	 *    up, so a bare two-label suffix passes through as if it were a real domain. Left
	 *    standing, "@co.uk" would match every .co.uk sender INCLUDING the operator's own
	 *    address — the guard would be there and still not guard. Measured against a site
	 *    on "site.co.uk" before this check existed.
	 * 3. An empty label (leading, trailing or doubled dot, e.g. "@.com" or "@x.com.").
	 *    Such an entry can never equal a real sender domain anyway.
	 *
	 * @param string   $domain      Domain part of the entry, WITHOUT the leading "@".
	 * @param string[] $own_domains Registrable domains of the site itself.
	 * @return bool
	 */
	public static function is_blockable_sender_domain( $domain, $own_domains = array() ) {
		$domain = strtolower( trim( (string) $domain ) );
		if ( '' === $domain ) {
			return false;
		}
		if ( in_array( '', explode( '.', $domain ), true ) ) {
			return false;
		}
		if ( in_array( $domain, self::MULTI_PART_SUFFIXES, true ) ) {
			return false;
		}
		return null !== self::registrable_domain( $domain, $own_domains );
	}

	/**
	 * Whether the sender domain of an already-lowercased email address is covered by
	 * one of the blocked sender domains (the "@domain" wildcard form, "@" already
	 * stripped). The sender domain is the part behind the LAST "@" — an address may
	 * legally quote an "@" in its local part, and the domain is always the tail.
	 *
	 * A blocked entry covers the exact domain and any subdomain of it. The suffix is
	 * matched WITH the separating dot on purpose: comparing against a bare "gmail.com"
	 * suffix would also swallow "notgmail.com", i.e. block an unrelated third party.
	 *
	 * @param string   $email           Lower-cased email address (from extract_emails()).
	 * @param string[] $blocked_domains Blocked sender domains, normalized, without "@".
	 * @return bool
	 */
	private static function email_has_blocked_sender_domain( $email, $blocked_domains ) {
		if ( empty( $blocked_domains ) ) {
			return false;
		}
		$at = strrpos( $email, '@' );
		if ( false === $at ) {
			return false;
		}
		$sender_domain = strtolower( substr( $email, $at + 1 ) );
		if ( '' === $sender_domain ) {
			return false;
		}
		foreach ( $blocked_domains as $blocked ) {
			if ( $sender_domain === $blocked ) {
				return true;
			}
			$suffix = '.' . $blocked;
			$offset = strlen( $sender_domain ) - strlen( $suffix );
			if ( $offset > 0 && substr( $sender_domain, $offset ) === $suffix ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Find URL-like substrings in a text value (http(s):// or bare www.).
	 *
	 * @param string $text Value.
	 * @return string[] Raw URL substrings.
	 */
	public static function extract_urls( $text ) {
		$text = (string) $text;
		if ( '' === $text ) {
			return array();
		}
		$matches = array();
		if ( preg_match_all( '#(?:https?://|www\.)[^\s<>"\'\)\]\},;]+#i', $text, $found ) ) {
			$matches = $found[0];
		}
		return $matches;
	}

	/**
	 * Find email addresses in a text value, trimmed + lowercased.
	 *
	 * @param string $text Value.
	 * @return string[] Lower-cased email addresses.
	 */
	public static function extract_emails( $text ) {
		$text = (string) $text;
		if ( '' === $text ) {
			return array();
		}
		$emails = array();
		if ( preg_match_all( '/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/', $text, $found ) ) {
			foreach ( $found[0] as $email ) {
				$emails[] = strtolower( trim( $email ) );
			}
		}
		return array_values( array_unique( $emails ) );
	}

	/**
	 * Convenience: the first email found in a value, or null. Used by the one-click
	 * "Block this sender" callback.
	 *
	 * @param string $text Value.
	 * @return string|null
	 */
	public static function extract_email( $text ) {
		$emails = self::extract_emails( $text );
		return empty( $emails ) ? null : $emails[0];
	}

	/**
	 * SHA-256 hashes of a list of raw email addresses, normalized (trim + lowercase)
	 * exactly like extract_emails(), so a hash produced here is bit-identical to the
	 * one build_echo_set() would emit for the same address. Empty/blank entries are
	 * dropped, the result is de-duplicated.
	 *
	 * Used by the WP glue (Echo_Store) to build the exclude set of registered-user
	 * emails: a value that belongs to a real user account must never be recorded as,
	 * or matched against, an echo value — otherwise an attacker who submits spam
	 * carrying a legitimate user's address could get that user echo-locked and thereby
	 * blocked at login / password-reset (the check runs there too). GDPR: only the
	 * hashes leave this method, never the plaintext addresses.
	 *
	 * @param string[] $emails Raw email addresses.
	 * @return string[] Unique SHA-256 hashes (lower-case hex).
	 */
	public static function hash_emails( $emails ) {
		$out = array();
		foreach ( (array) $emails as $email ) {
			$normalized = strtolower( trim( (string) $email ) );
			if ( '' !== $normalized ) {
				$out[ self::hash_value( $normalized ) ] = true;
			}
		}
		return array_keys( $out );
	}

	/**
	 * The registrable domain (eTLD+1) of a URL, or null when it does not resolve to
	 * a real domain (bare word, IP literal — the explicit NOT-IP rule — or one of
	 * the $own_domains). For a PATH_IDENTITY_HOSTS host the result is
	 * "host/first-path-segment". Accepts a full URL, a scheme-less URL, or a bare
	 * host/domain.
	 *
	 * @param string   $url          URL, scheme-less URL, or bare domain.
	 * @param string[] $own_domains  Registrable domains of the site itself, excluded.
	 * @return string|null
	 */
	public static function registrable_domain( $url, $own_domains = array() ) {
		$url = trim( (string) $url );
		if ( '' === $url ) {
			return null;
		}
		// Strip scheme.
		$url = (string) preg_replace( '#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', '', $url );

		// Split host(+port) from path/query/fragment at the first slash.
		$host_part = $url;
		$path_part = '';
		$slash     = strpos( $url, '/' );
		if ( false !== $slash ) {
			$host_part = substr( $url, 0, $slash );
			$path_part = substr( $url, $slash + 1 );
		}
		// Drop query/fragment attached without a slash (host?x=1 / host#a).
		foreach ( array( '?', '#' ) as $separator ) {
			$position = strpos( $host_part, $separator );
			if ( false !== $position ) {
				$host_part = substr( $host_part, 0, $position );
			}
		}
		// Strip any leading userinfo (the part before an at-sign).
		$at = strrpos( $host_part, '@' );
		if ( false !== $at ) {
			$host_part = substr( $host_part, $at + 1 );
		}

		$host = strtolower( trim( $host_part ) );
		if ( '' === $host ) {
			return null;
		}
		// Bracketed IPv6 literal → not a domain (explicit NOT-IP rule).
		if ( '[' === $host[0] ) {
			return null;
		}
		// Strip a leading www.
		if ( 0 === strpos( $host, 'www.' ) ) {
			$host = substr( $host, 4 );
		}
		// Strip :port.
		$colon = strpos( $host, ':' );
		if ( false !== $colon ) {
			$host = substr( $host, 0, $colon );
		}
		if ( '' === $host ) {
			return null;
		}
		// IPv4 literal → not a domain (explicit NOT-IP rule).
		if ( false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		// Needs at least one dot to be a domain.
		if ( false === strpos( $host, '.' ) ) {
			return null;
		}

		// Path-identity hosts: domain + first path segment is the identity.
		if ( in_array( $host, self::PATH_IDENTITY_HOSTS, true ) ) {
			if ( in_array( $host, $own_domains, true ) ) {
				return null;
			}
			$result = $host;
			if ( '' !== $path_part ) {
				$segment = $path_part;
				foreach ( array( '/', '?', '#' ) as $separator ) {
					$position = strpos( $segment, $separator );
					if ( false !== $position ) {
						$segment = substr( $segment, 0, $position );
					}
				}
				$segment = strtolower( trim( $segment ) );
				if ( '' !== $segment ) {
					$result = $host . '/' . $segment;
				}
			}
			return $result;
		}

		// eTLD+1 via the curated multi-part suffix list.
		$labels   = explode( '.', $host );
		$count    = count( $labels );
		$last_two = $labels[ $count - 2 ] . '.' . $labels[ $count - 1 ];
		if ( $count >= 3 && in_array( $last_two, self::MULTI_PART_SUFFIXES, true ) ) {
			$domain = $labels[ $count - 3 ] . '.' . $last_two;
		} else {
			$domain = $last_two;
		}
		if ( in_array( $domain, $own_domains, true ) ) {
			return null;
		}
		return $domain;
	}

	/**
	 * Normalize a value to a bare phone digit-string, or null when it is not
	 * phone-shaped. Value-based (not field-name-based) detection is deliberate: the
	 * field name varies across form builders (the very problem this feature solves),
	 * so a shape guard on the value is more robust. A leading "+" becomes a "00"
	 * prefix; the value must carry at least PHONE_MIN_DIGITS digits so arbitrary
	 * numbers (order totals, years) are not mistaken for phone numbers.
	 *
	 * @param string $value Value.
	 * @return string|null Digit string, or null.
	 */
	public static function normalize_phone( $value ) {
		$value = trim( (string) $value );
		if ( '' === $value ) {
			return null;
		}
		// Shape guard: only phone-plausible characters.
		if ( 1 !== preg_match( '#^\+?[0-9 ()/.\-]{6,}$#', $value ) ) {
			return null;
		}
		$has_plus = 0 === strpos( $value, '+' );
		$digits   = (string) preg_replace( '/\D+/', '', $value );
		if ( strlen( $digits ) < self::PHONE_MIN_DIGITS ) {
			return null;
		}
		return $has_plus ? '00' . $digits : $digits;
	}

	/**
	 * Normalize a text value (lower-case, strip everything but letters/digits) for
	 * the exact-resend text hash, or null when it is shorter than
	 * TEXT_HASH_MIN_LENGTH normalized characters. Deliberately exact, not fuzzy.
	 *
	 * @param string $value Value.
	 * @return string|null Normalized text, or null.
	 */
	public static function normalize_text( $value ) {
		$value = (string) $value;
		if ( '' === $value || 1 !== preg_match( '//u', $value ) ) {
			return null;
		}
		$lower      = function_exists( 'mb_strtolower' ) ? mb_strtolower( $value, 'UTF-8' ) : strtolower( $value );
		$normalized = (string) preg_replace( '/[^\p{L}\p{N}]+/u', '', $lower );
		$length     = function_exists( 'mb_strlen' ) ? mb_strlen( $normalized, 'UTF-8' ) : strlen( $normalized );
		if ( $length < self::TEXT_HASH_MIN_LENGTH ) {
			return null;
		}
		return $normalized;
	}

	/**
	 * Build the set of echo hashes for a submission: the SHA-256 of every extracted
	 * core value (sender email, payload domain/path-identity, phone, long-text). The
	 * site's own registrable domain(s) are excluded from URL extraction. The result
	 * contains ONLY 64-char hex hashes — never a plaintext value (GDPR).
	 *
	 * @param mixed    $fields          Field map (user-content extraction; technical keys skipped).
	 * @param string[] $own_domains     Registrable domains of the site itself, excluded.
	 * @param string[] $excluded_hashes SHA-256 hashes that must never be emitted (e.g.
	 *                                  registered-user email hashes from hash_emails()).
	 *                                  A THIRD, value-level defense line alongside the
	 *                                  technical-key skip (invariant 1) and the own-domain
	 *                                  drop (invariant 2): it lets the WP glue keep any
	 *                                  value that belongs to a real account out of the echo
	 *                                  lock, so submitting spam with a user's address cannot
	 *                                  lock that user out at login/password-reset.
	 * @return string[] Unique SHA-256 hashes.
	 */
	public static function build_echo_set( $fields, $own_domains = array(), $excluded_hashes = array() ) {
		$hashes = array();
		foreach ( self::collect_content_strings( $fields ) as $value ) {
			foreach ( self::extract_emails( $value ) as $email ) {
				$hashes[ self::hash_value( $email ) ] = true;
			}
			foreach ( self::extract_urls( $value ) as $url ) {
				$domain = self::registrable_domain( $url, $own_domains );
				if ( null !== $domain ) {
					$hashes[ self::hash_value( $domain ) ] = true;
				}
			}
			$phone = self::normalize_phone( $value );
			if ( null !== $phone ) {
				$hashes[ self::hash_value( $phone ) ] = true;
			}
			$text = self::normalize_text( $value );
			if ( null !== $text ) {
				$hashes[ self::hash_value( $text ) ] = true;
			}
		}
		foreach ( (array) $excluded_hashes as $excluded ) {
			unset( $hashes[ $excluded ] );
		}
		return array_keys( $hashes );
	}
}
