<?php
/**
 * The BLOCKLIST half of Echo_Values: what a configured line IS, and what it HITS.
 *
 * SCHNITTLINIE (Welle 4, PLAN-DATEIGROESSE.md): class-echo-values.php was one file of
 * 1026 lines. It is split along the seam its own head docblock already names:
 *   - class-echo-values.php      — the EXTRACTION half: what a submission contains
 *                                  (content-string walk, email/URL/phone/text
 *                                  normalisation, registrable domain, build_echo_set()).
 *   - trait-blocklist-values.php — THIS file: the BLOCKLIST half. Reading the option's
 *                                  lines (partition_blocklist_lines() and the two
 *                                  wrappers around it) and comparing them against a
 *                                  submission (matches_wildcard_values(),
 *                                  blocked_entry_matches(), blocked_emails(),
 *                                  all_emails_exempt()).
 *
 * A TRAIT, NOT A SECOND CLASS, and that is the whole point of the seam. The comparison
 * rules of this plugin exist EXACTLY ONCE — split_wildcard_values(), email_is_blocked()
 * and string_hits() are shared by "does anything match at all?"
 * (matches_wildcard_values()), "which addresses did the matching?" (blocked_emails(),
 * i.e. the login exemption) and "does this ONE field match?" (blocked_entry_matches(),
 * the value half of a field-bound rule). handbuch/detection.md says "genau einmal" about
 * that in three places, and a second class would have meant either moving those three
 * privates away from one of their callers or repeating them. A trait is compiled into
 * Echo_Values at compile time: all three still live in one file, every caller still
 * writes Echo_Values::…, and no test, no pin and no visibility changes. The split is a
 * move, not a rebuild.
 *
 * Consequence for the loader: a trait must be loaded BEFORE the class that uses it —
 * see the require_once order in plugin/recaptcha-gdpr-compliant.php, tests/bootstrap.php
 * and tests/replay/replay.php. This file is also listed in loop/worker/rails.mjs'
 * DETECTION_FILES, for the same reason class-echo-values.php is: a change here is a
 * change to the detection.
 *
 * Pure, WordPress-independent, exactly like the class it belongs to —
 * tests/unit/EchoValuesTest.php exercises it through Echo_Values.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse (Traits
// bekommen keine eigene Indexzeile; sie sind Teil ihrer Klasse).

/**
 * Reading and matching the operator's blocklist. Composed into Echo_Values.
 */
trait Blocklist_Values {

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
		$partition = self::partition_blocklist_lines( $lines );
		return $partition['values'];
	}

	/**
	 * Read the blocklist option's lines into the THREE things a line can be. The ONE place
	 * that decides which of them a given line is — every consumer asks this, nobody
	 * re-reads a line itself.
	 *
	 * THE SHORT FORM STAYS THE SHORT FORM. A line that does not start with "{" is a plain
	 * value for ALL fields, byte-for-byte what it has always been (owner decision: no
	 * second migration four weeks after the first, and the one-click "Block this
	 * sender/domain" buttons keep writing readable addresses instead of JSON). Only a line
	 * that starts with "{" is read as a RULE.
	 *
	 * THE WILDCARD IS FOLDED, and that is load-bearing rather than tidiness:
	 * `{"*":"@spam.tld"}` is the long spelling of `@spam.tld`, so it must be the SAME thing
	 * everywhere, not merely a thing that usually behaves the same. Left in the rule set it
	 * would take part in the field-bound rule path — and would therefore silently drop out
	 * of the login exemption for registered users (Stamp::is_exempt_login_submission()
	 * computes its address set B from the VALUES) and out of the technical-key skip
	 * (invariant 1). Two spellings of one entry that lock a different set of people out is
	 * exactly the "two semantics" failure this plugin spends so much care avoiding. Only a
	 * single-key `*` with a non-empty STRING value folds — everything else about `*` keeps
	 * the reading Pattern_Matcher gives it.
	 *
	 * AN UNREADABLE LINE IS NAMED, NOT REINTERPRETED. A line starting with "{" that does
	 * not decode to a non-empty JSON object comes back as `invalid`: it never matches
	 * anything (fail-open at match time — a typo that blocked every submission site-wide
	 * would be the most expensive mistake this plugin can make), and the settings page says
	 * so at save time, which is what keeps "inert" from meaning "silently dead". It is
	 * deliberately NOT fallen back to its whole-value meaning: one line that means two
	 * different things depending on whether it happens to parse would be worse than either
	 * reading alone.
	 *
	 * @param string[] $lines Raw blocklist lines.
	 * @return array{values: string[], rules: string[], invalid: string[]} Normalized plain
	 *               values (short form plus folded wildcards), raw rule lines, and lines
	 *               that are neither. Each list unique, in input order.
	 */
	public static function partition_blocklist_lines( $lines ) {
		$values  = array();
		$rules   = array();
		$invalid = array();
		foreach ( (array) $lines as $raw_line ) {
			$line = trim( (string) $raw_line );
			if ( '' === $line ) {
				continue;
			}
			if ( '{' !== $line[0] ) {
				// $line is already trimmed and non-empty, so the normalized form is too.
				$values[] = self::normalize_wildcard( $line );
				continue;
			}
			// Deliberately no assoc flag, exactly as Pattern_Matcher::line_matches() decodes
			// a pattern line — the rule is handed to that very matcher, and a line must not
			// decode differently depending on who reads it.
			$decoded = json_decode( $line );
			$map     = is_object( $decoded ) ? get_object_vars( $decoded ) : array();
			if ( empty( $map ) ) {
				$invalid[] = $line;
				continue;
			}
			if ( 1 === count( $map ) && array_key_exists( '*', $map ) && is_string( $map['*'] ) ) {
				$value = self::normalize_wildcard( $map['*'] );
				if ( '' !== $value ) {
					$values[] = $value;
				} else {
					$invalid[] = $line;
				}
				continue;
			}
			$rules[] = $line;
		}
		return array(
			'values'  => array_values( array_unique( $values ) ),
			'rules'   => array_values( array_unique( $rules ) ),
			'invalid' => array_values( array_unique( $invalid ) ),
		);
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
			if ( self::string_hits( $string, $set, $sender_domains, $own_domains ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * THE four comparisons of matches_wildcard_values(), applied to ONE string. Factored
	 * out so the field-bound block RULES (a blocklist line written as a JSON object, see
	 * partition_blocklist_lines()) can ask the very same question about the value of ONE
	 * named field, instead of a second rendering of "what does a blocked value mean".
	 *
	 * Nothing about the comparisons changed when they moved here; the loop above is the
	 * only thing that stayed behind. The order is irrelevant to the result (any hit wins)
	 * but is kept as it was so a diff of this file stays readable.
	 *
	 * @param string            $text           One raw value.
	 * @param array<string,int> $set            Exact-value lookup set from split_wildcard_values().
	 * @param string[]          $sender_domains Blocked sender domains from split_wildcard_values().
	 * @param string[]          $own_domains    Registrable domains of the site itself.
	 * @return bool
	 */
	private static function string_hits( $text, $set, $sender_domains, $own_domains ) {
		if ( isset( $set[ self::normalize_wildcard( $text ) ] ) ) {
			return true;
		}
		foreach ( self::extract_emails( $text ) as $email ) {
			if ( self::email_is_blocked( $email, $set, $sender_domains ) ) {
				return true;
			}
		}
		foreach ( self::extract_urls( $text ) as $url ) {
			$domain = self::registrable_domain( $url, $own_domains );
			if ( null !== $domain && isset( $set[ $domain ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Does ONE blocklist entry hit the value at ONE position of a submission? The value
	 * half of a block RULE — Pattern_Matcher::matches() calls this wherever a monitoring
	 * pattern would compare strictly, and nowhere else (see the "second named exception"
	 * paragraph in that class's header).
	 *
	 * TWO POSITIONS, one rule each:
	 * - $any_field = true — the entry sits under the rule key `*`, so the question is the
	 *   site-wide one and the answer is literally matches_wildcard_values() over the
	 *   subtree. That is not an optimisation: routing it through the same function is what
	 *   makes `{"*":"@x.tld"}` behave identically to the short form `@x.tld`, INCLUDING the
	 *   technical-key skip (invariant 1) and the own-domain exclusion (invariant 2).
	 * - $any_field = false — the entry sits under a field NAME, so exactly that field's
	 *   value is compared, with the four forms. The technical-key skip deliberately does
	 *   NOT apply here: naming `_wpcf7` is how a rule binds itself to one FORM, and a skip
	 *   would make the documented form-binding silently impossible. A non-scalar (or
	 *   absent) value never hits, which keeps the isset()-shaped reading of the strict
	 *   comparison this replaces.
	 *
	 * @param string|int|float|bool $entry One blocklist entry, raw (normalized — i.e.
	 *                                     cast to string, trimmed, lowercased — here; a
	 *                                     block RULE may carry any JSON scalar).
	 * @param mixed    $context     The subtree ($any_field) or the field value to test.
	 * @param bool     $any_field   Whether $entry came from the `*` key.
	 * @param string[] $own_domains Registrable domains of the site itself.
	 * @return bool
	 */
	public static function blocked_entry_matches( $entry, $context, $any_field, $own_domains = array() ) {
		$value = self::normalize_wildcard( $entry );
		if ( '' === $value ) {
			return false;
		}
		if ( $any_field ) {
			return self::matches_wildcard_values( $context, array( $value ), $own_domains );
		}
		if ( ! is_scalar( $context ) ) {
			return false;
		}
		list( $set, $sender_domains ) = self::split_wildcard_values( array( $value ), $own_domains );
		return self::string_hits( (string) $context, $set, $sender_domains, $own_domains );
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
}
