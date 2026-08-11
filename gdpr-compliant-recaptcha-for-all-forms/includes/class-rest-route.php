<?php
/**
 * Pure, WordPress-independent extraction and pattern-matching of the REST route a
 * request targets — the third signature class alongside admin-ajax actions
 * (Explicit mode) and field patterns (see class-stamp.php / handbuch/gate.md).
 *
 * A REST submission carries neither an `action` parameter nor (usually) a field
 * pattern the plugin already knows, so builders that submit over the REST API
 * (WS Form, Otter Blocks; Contact Form 7 also submits this way but is already
 * covered by its `_wpcf7` pattern) were structurally invisible to the scope. The
 * ROUTE is the stable identifier of a REST submission, the counterpart to `action`.
 *
 * TWO SOURCES, because WordPress exposes REST requests two different ways depending
 * on the permalink structure — see REST_ROUTES_PLAN.md §0:
 *   - Plain permalinks: the route travels as the `rest_route` query parameter
 *     (`/?rest_route=/wp/v2/posts`), never in REQUEST_URI's path.
 *   - Pretty permalinks: the route is baked into REQUEST_URI's path, prefixed by
 *     the site's home path and the REST prefix (`rest_get_url_prefix()`, 'wp-json'
 *     by default but changeable via the `rest_url_prefix` filter — never hardcode
 *     it here, the caller supplies it).
 * Both normalize to the same canonical form: a leading slash, no query string, no
 * trailing slash, URL-decoded.
 *
 * CASE HANDLING IS NOT UNIFORM, because WordPress' own routing is not uniform, and
 * every divergence here is a full bypass (the request reaches the endpoint, we do not
 * see it). Verified against WordPress core, see the individual methods:
 *   - route vs. pattern   -> case-INsensitive (WP_REST_Server::match_request_to_handler()
 *                            matches with the `i` modifier).
 *   - home path           -> case-INsensitive (WP::parse_request() strips it with
 *                            `|^…|i`).
 *   - REST prefix,        -> case-SENSITIVE (rewrite rules are matched WITHOUT the `i`
 *     `index.php`            modifier, so WordPress itself 404s on `/WP-JSON/…`).
 *
 * No WordPress dependencies (no $_SERVER/$_GET, no options, no rest_get_url_prefix()
 * call) — this class only turns already-collected strings into a route/verdict, which
 * makes it unit-testable in isolation. See tests/unit/RestRouteTest.php.
 * Stamp::check_rest_routes() collects the WP-specific inputs and delegates here.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/gate.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Stateless REST-route extraction/matching helpers.
 */
final class RestRoute {

	/**
	 * WordPress' OWN REST namespaces — the ones wp-admin itself submits to, and the
	 * ones an admin must never be able to put into POW_REST_ROUTES (see
	 * reject_self_lockout_lines()). `wp/v2` is the block editor's save route,
	 * `wp-site-health`/`wp-block-editor` are admin-screen backends, `oembed` is core
	 * too. Not "every namespace of every plugin" — only the ones whose loss takes
	 * wp-admin itself down.
	 *
	 * @var string[]
	 */
	const CORE_NAMESPACES = array(
		'wp/v2',
		'wp/v1',
		'wp-site-health',
		'wp-block-editor',
		'oembed',
		// The Abilities API's own REST surface (core since WP 6.9) and the namespace
		// the official WordPress/mcp-adapter serves its server under. Neither is
		// wp-admin, so neither fits the "takes wp-admin down" rule above — they are
		// here for the other half of the same idea: these are the channels through
		// which an agent reaches this site at all. Putting them behind the PoW gate
		// would let one scope entry cut off the caller that made it (and every other
		// plugin's abilities with it), with no way back from the outside. Since
		// Scope_Add exposes exactly this option to an agent, the guard has to cover
		// them before the ability does.
		'wp-abilities/v1',
		'mcp',
	);

	/**
	 * Extract and normalize the REST route a request targets, or null if this is
	 * not (recognizably) a REST request at all.
	 *
	 * @param string $request_uri      Raw REQUEST_URI, exactly as received (may
	 *                                 carry a query string, NOT URL-decoded — this
	 *                                 is what PHP puts in $_SERVER['REQUEST_URI']).
	 * @param string $rest_route_param The `rest_route` query parameter, e.g. from
	 *                                 $_GET['rest_route']. Pass '' if absent. PHP's
	 *                                 own superglobal parsing already URL-decodes
	 *                                 this once, so — unlike $request_uri — it is
	 *                                 NOT decoded again here.
	 * @param string $home_path        Path component of the site's `home` option,
	 *                                 WITHOUT trailing slash ('' at the domain
	 *                                 root, e.g. '/blog' for a subdirectory
	 *                                 install).
	 * @param string $rest_prefix      The REST URL prefix (`rest_get_url_prefix()`,
	 *                                 'wp-json' by default). Never hardcode this —
	 *                                 the `rest_url_prefix` filter can change it.
	 * @return string|null Canonical route ('/namespace/version/…'), or null.
	 */
	public static function extract( $request_uri, $rest_route_param, $home_path, $rest_prefix ) {
		$rest_route_param = (string) $rest_route_param;
		if ( '' !== trim( $rest_route_param ) ) {
			$segments = self::segments( $rest_route_param );
			if ( ! empty( $segments ) ) {
				return '/' . implode( '/', $segments );
			}
		}

		$path          = self::path_only( (string) $request_uri );
		$path_segments = self::segments( rawurldecode( $path ) );
		$offset        = 0;

		// 1. Home path — compared CASE-INSENSITIVELY, because WordPress strips it
		// that way: WP::parse_request() builds `sprintf( '|^%s|i', preg_quote(…) )`
		// from the home path and preg_replace()s it off REQUEST_URI
		// (wp-includes/class-wp.php). A subdirectory install therefore serves
		// `/BLOG/wp-json/…` just as it serves `/blog/wp-json/…`.
		foreach ( self::segments( (string) $home_path ) as $home_segment ) {
			if ( ! isset( $path_segments[ $offset ] ) || 0 !== strcasecmp( $path_segments[ $offset ], $home_segment ) ) {
				return null;
			}
			++$offset;
		}

		// 2. An OPTIONAL `index.php` between home path and REST prefix. WordPress
		// registers its own rewrite rules for this spelling —
		// `'^' . $wp_rewrite->index . '/' . rest_get_url_prefix() . '/(.*)?'` in
		// rest_api_register_rewrites() (wp-includes/rest-api.php) — so
		// `/index.php/wp-json/wp/v2/posts` is dispatched exactly like
		// `/wp-json/wp/v2/posts`. Compared case-sensitively for the same reason as
		// the prefix below: it is part of a rewrite rule / a real filename.
		if ( isset( $path_segments[ $offset ] ) && 'index.php' === $path_segments[ $offset ] ) {
			++$offset;
		}

		// 3. REST prefix — CASE-SENSITIVE, deliberately, and NOT an oversight to be
		// "fixed" later: WP::parse_request() matches rewrite rules with
		// `preg_match( "#^$match#", … )`, WITHOUT the `i` modifier, so WordPress
		// itself does not route `/WP-JSON/wp/v2/posts` to the REST server at all —
		// it 404s. Making this case-insensitive would make us see routes WordPress
		// never serves, not close a gap.
		foreach ( self::segments( (string) $rest_prefix ) as $prefix_segment ) {
			if ( ! isset( $path_segments[ $offset ] ) || $path_segments[ $offset ] !== $prefix_segment ) {
				return null;
			}
			++$offset;
		}

		$route_segments = array_slice( $path_segments, $offset );
		if ( empty( $route_segments ) ) {
			// Nothing left after the prefix — not a REST request, or a bare
			// namespace root.
			return null;
		}
		return '/' . implode( '/', $route_segments );
	}

	/**
	 * Whether $route matches any line of $patterns (one route/namespace per line,
	 * blank lines ignored). Patterns are admin input, never treated as regex —
	 * every segment is compared as a plain string, so regex metacharacters, `../`
	 * segments, etc. in a pattern are inert.
	 *
	 * CASE-INSENSITIVE, because WordPress' own route matching is:
	 * WP_REST_Server::match_request_to_handler() compares the requested path against
	 * every registered route with `preg_match( '@^' . $route . '$@i', $path )`
	 * (wp-includes/rest-api/class-wp-rest-server.php). `?rest_route=/WP/V2/posts` is
	 * therefore served by the very same handler as `/wp/v2/posts` — matching
	 * case-sensitively here would have left an upper-case spelling of any monitored
	 * route as a complete bypass. Folding is ASCII-only (strcasecmp), which is also
	 * what PCRE's `i` does on a non-UTF-8 subject.
	 *
	 * Two wildcard forms, told apart by POSITION, not by a different character:
	 *   - `*` as any segment EXCEPT the last one matches exactly that one segment
	 *     (e.g. a CF7 form ID: `contact-form-7/v1/contact-forms/*\/feedback`).
	 *   - `*` as the LAST segment matches the fixed prefix before it plus any
	 *     number (zero or more) of further segments — a namespace suffix
	 *     (`ws-form/v1/*` matches `/ws-form/v1/submit`, `/ws-form/v1/submit/42`, …).
	 *
	 * @param string $route    Canonical or raw route; re-segmented either way.
	 * @param string $patterns Newline-separated pattern lines.
	 * @return bool
	 */
	public static function matches( $route, $patterns ) {
		$route_segments = self::segments( (string) $route );
		if ( empty( $route_segments ) ) {
			return false;
		}

		$lines = preg_split( '/\r\n|\n|\r/', (string) $patterns, -1, PREG_SPLIT_NO_EMPTY );
		if ( false === $lines ) {
			return false;
		}

		foreach ( $lines as $line ) {
			$pattern_segments = self::segments( trim( $line ) );
			if ( empty( $pattern_segments ) ) {
				continue;
			}
			if ( self::segments_match( $route_segments, $pattern_segments ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * SAVE-TIME GUARD against the administrator locking themselves out of their own
	 * wp-admin (REST_ROUTES_PLAN.md AP6 failure mode, made unreachable here rather
	 * than only warned about in the option's help text).
	 *
	 * A line covering a core namespace is not a mild misconfiguration, it is a dead
	 * end: POW_BLOCK is on by default, so the block editor's own save
	 * (`/wp/v2/posts/<id>`) is discarded as spam — and wp-admin never receives the
	 * PoW script, so the administrator cannot solve a challenge to get out of it
	 * either. The only remaining exits are the database or FTP.
	 *
	 * Deliberately CONSERVATIVE: a line is rejected as soon as its route set
	 * OVERLAPS a core namespace, not only when it is that namespace. `wp/v2`,
	 * `wp/v2/*`, `wp/*`, `wp/v2/posts/123` and a line whose FIRST segment is a
	 * wildcard followed by `v2/posts` all go; a bare `*` goes
	 * because it covers literally every route (checked separately below, so the
	 * intent is explicit and not a side effect of the namespace list). Builder lines
	 * (`ws-form/v1/*`, `otter/v1/form/frontend`, `contact-form-7/v1/…`) are
	 * unaffected — they share no leading segment with any core namespace.
	 *
	 * Pure: no options, no notices, no WordPress. Settings_Menu::update_settings()
	 * saves the returned value and reports the returned lines to the admin (never
	 * swallowing them silently); the rest of the input is saved normally.
	 *
	 * @param string $value Raw textarea value as submitted.
	 * @return array{0:string,1:string[]} [ value to store, rejected lines (as entered) ].
	 */
	public static function reject_self_lockout_lines( $value ) {
		$lines = preg_split( '/\r\n|\n|\r/', (string) $value );
		if ( false === $lines ) {
			return array( (string) $value, array() );
		}

		$kept     = array();
		$rejected = array();
		foreach ( $lines as $line ) {
			$segments = self::segments( trim( $line ) );
			if ( empty( $segments ) || ! self::is_self_lockout_pattern( $segments ) ) {
				$kept[] = $line;
				continue;
			}
			$rejected[] = trim( $line );
		}

		return array( implode( "\n", $kept ), $rejected );
	}

	/**
	 * Whether a pattern's route set overlaps a core namespace (or everything).
	 *
	 * @param string[] $pattern_segments Non-empty pattern segments.
	 * @return bool
	 */
	private static function is_self_lockout_pattern( array $pattern_segments ) {
		// A bare `*` is a namespace-suffix wildcard with an EMPTY fixed part, i.e. it
		// matches every route there is — including every core one.
		if ( array( '*' ) === $pattern_segments ) {
			return true;
		}

		foreach ( self::CORE_NAMESPACES as $namespace ) {
			if ( self::overlaps_namespace( $pattern_segments, self::segments( $namespace ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether ANY route below $namespace_segments could match $pattern_segments.
	 *
	 * Mirrors segments_match()'s two wildcard forms, but compares only as far as the
	 * shorter of the two: a namespace-suffix pattern (`wp/*`) matches everything
	 * below its fixed part, and a fixed-length pattern (`wp/v2/posts/123`) can only
	 * reach into the namespace if it is at least as long as it.
	 *
	 * @param string[] $pattern_segments   Non-empty.
	 * @param string[] $namespace_segments Non-empty.
	 * @return bool
	 */
	private static function overlaps_namespace( array $pattern_segments, array $namespace_segments ) {
		$last_index          = count( $pattern_segments ) - 1;
		$is_namespace_suffix = '*' === $pattern_segments[ $last_index ];
		$fixed_pattern       = $is_namespace_suffix ? array_slice( $pattern_segments, 0, $last_index ) : $pattern_segments;

		if ( ! $is_namespace_suffix && count( $fixed_pattern ) < count( $namespace_segments ) ) {
			// Too short to ever reach a route INSIDE the namespace — e.g. the line
			// `wp` only matches the one-segment route `/wp`, never `/wp/v2/posts`.
			return false;
		}

		$compare = min( count( $fixed_pattern ), count( $namespace_segments ) );
		for ( $i = 0; $i < $compare; $i++ ) {
			if ( '*' === $fixed_pattern[ $i ] ) {
				continue;
			}
			if ( 0 !== strcasecmp( $fixed_pattern[ $i ], $namespace_segments[ $i ] ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @param string[] $route_segments
	 * @param string[] $pattern_segments Non-empty.
	 * @return bool
	 */
	private static function segments_match( array $route_segments, array $pattern_segments ) {
		$last_index          = count( $pattern_segments ) - 1;
		$is_namespace_suffix = '*' === $pattern_segments[ $last_index ];
		$fixed_pattern       = $is_namespace_suffix ? array_slice( $pattern_segments, 0, $last_index ) : $pattern_segments;

		if ( $is_namespace_suffix ) {
			if ( count( $route_segments ) < count( $fixed_pattern ) ) {
				return false;
			}
		} elseif ( count( $route_segments ) !== count( $fixed_pattern ) ) {
			return false;
		}

		foreach ( $fixed_pattern as $i => $pattern_segment ) {
			if ( '*' === $pattern_segment ) {
				continue; // Single-segment wildcard: matches anything in this position.
			}
			// Case-insensitive, see matches()' doc-comment (WP matches routes with `@…@i`).
			if ( 0 !== strcasecmp( $route_segments[ $i ], $pattern_segment ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The path component of a request-target string, i.e. everything before the
	 * first '?' or '#'. Plain string scanning, no parse_url() — REQUEST_URI is a
	 * request-target, not a full URL, and parse_url() mishandles some malformed-
	 * but-real-world values (e.g. a literal '?' inside an otherwise path-only
	 * value coming from a misbehaving client).
	 *
	 * @param string $uri
	 * @return string
	 */
	private static function path_only( $uri ) {
		return substr( $uri, 0, strcspn( $uri, '?#' ) );
	}

	/**
	 * Canonicalize a route that was NOT extracted from this request's own $_SERVER —
	 * i.e. one that arrives as data and therefore cannot be trusted to have the shape
	 * extract() guarantees.
	 *
	 * The one caller today is Analysis::store_analysis_entry_data(): the direct-analysis
	 * overlay detects the route in the browser and ships it inside the captured entry, so
	 * the string reaching the server is client-supplied. The endpoint is `manage_options`
	 * + nonce, so this is not an anonymous input — but the value is written to a detail
	 * row that the message view later renders and offers as a one-click "Monitor this
	 * route", and a route is a matching rule. Validating beats trusting, at the price of
	 * three lines.
	 *
	 * ALLOWLIST, not a blocklist: segments may hold letters, digits, `_`, `.` and `-`
	 * only — the character set WordPress' own `register_rest_route()` namespaces and
	 * routes use. Anything else (a `%`-escape, a slash-encoded traversal, whitespace, a
	 * quote) makes the whole value null rather than being stripped: a route that had to
	 * be repaired is a route nobody wrote. `.` and `..` segments are rejected outright.
	 * Length is bounded so a pathological string cannot reach the row at all.
	 *
	 * @param mixed $value Raw route candidate, e.g. from a decoded JSON payload.
	 * @return string|null Canonical route ('/namespace/version/…'), or null if unusable.
	 */
	public static function sanitize_route( $value ) {
		if ( ! is_string( $value ) || '' === $value || strlen( $value ) > 255 ) {
			return null;
		}
		$segments = self::segments( self::path_only( $value ) );
		if ( empty( $segments ) ) {
			return null;
		}
		foreach ( $segments as $segment ) {
			if ( '.' === $segment || '..' === $segment ) {
				return null;
			}
			// `\z`, NOT `$`: PCRE's `$` also matches BEFORE a trailing newline, so
			// `^[A-Za-z0-9_.-]+$` happily accepts "posts\n" — a route value with a line
			// break in it, which is precisely what an allowlist is here to prevent
			// (POW_REST_ROUTES is a line-separated option; one smuggled newline is two
			// rules). Caught by test_sanitize_route_rejects_anything_outside_the_allowlist.
			if ( ! preg_match( '/^[A-Za-z0-9_.-]+\z/', $segment ) ) {
				return null;
			}
		}
		return '/' . implode( '/', $segments );
	}

	/**
	 * Split a path/route into non-empty segments — trims leading/trailing
	 * slashes, collapses repeated slashes (double slashes yield no empty
	 * segment), tolerant of a trailing slash on the input.
	 *
	 * @param string $path
	 * @return string[]
	 */
	private static function segments( $path ) {
		$raw      = explode( '/', (string) $path );
		$segments = array();
		foreach ( $raw as $segment ) {
			if ( '' !== $segment ) {
				$segments[] = $segment;
			}
		}
		return $segments;
	}
}
