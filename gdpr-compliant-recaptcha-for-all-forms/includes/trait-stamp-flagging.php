<?php
/**
 * The field flagging of Stamp: "Fieldname:prefix to flag spam" (Option::POW_FLAG_SUFFIXES)
 * and "Fieldname:value to add" (Option::POW_FLAG_TAGS), applied to a spam submission that
 * is let through instead of blocked.
 *
 * SCHNITTLINIE (2026-10-29): moved out of check_submit() (class-stamp.php), which stood at
 * its size cap when the prefix fix below needed lines there. WHETHER flagging runs is
 * still decided in check_submit() — the one `if` that reads enforcement_allowed() stays
 * there (tests/unit/RiskEnforcementTest.php pins it); this file only does the writing.
 *
 * WHERE THE FLAG HAS TO LAND. The form builder reads its posted data from $_POST, not
 * from our copy of it ($request_data, captured by value in trait-stamp-capture.php) — so
 * a flag written only into the copy reaches the saved message but never the mail the
 * builder sends. Up to 4.0 the prefixes were written into $_POST. 4.1 (fix for JSON-based
 * submissions) switched every READ of $_POST to the copy, and the prefix WRITE went along
 * with it; the added fields kept their $_POST line. From then on the prefix reached the
 * saved message only — until a wp.org report (2026-10-28, Contact Form 7 over REST).
 * Now both again: $_POST for the builder, the copy for 4.1's JSON bodies. Measured:
 * tests/integration/cases/flag-spam-mail.mjs.
 *
 * JSON TEXT (2026-10-29, follow-up to the same report): a field inside an envelope ($_POST
 * field holding the whole form as JSON, e.g. Ninja Forms) or inside a JSON request body is
 * not a $_POST value. flag_inside_json() decodes, prefixes and re-encodes it (Flag_Prefix,
 * which also says why the encoding gives back what the browser sent) and writes it where
 * the builder reads. Limits: a builder that reads php://input itself, or `$_REQUEST` after
 * wp_magic_quotes() rebuilt it (a check deferred to `init` writes $_POST only); a check
 * over the raw body's bytes (a webhook HMAC) would see the change — irrelevant in practice,
 * since only flagged spam the operator lets through is touched.
 *
 * LOAD ORDER. Writing $_POST only helps a builder that reads it AFTER us. Ninja Forms copies
 * `formData` in a constructor that runs when its own plugin file is included (measured,
 * 3.15.7: ninja-forms.php calls Ninja_Forms() at file level). WordPress includes plugins in
 * the order of `active_plugins`, alphabetical by folder: on a real site our folder
 * `gdpr-compliant-recaptcha-for-all-forms` comes before `ninja-forms`, and the prefix
 * arrives (measured against the real plugin, both of its default mails). In wp-env our
 * folder is `plugin` and comes after — the reason the integration arm uses a stand-in
 * receiver instead. A builder that caches $_POST at include time and sorts before `g` would
 * miss the prefix the same way.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md, Abschnitt "Persistenz und Fail2Ban".
// Index/Absprungstelle: HANDBUCH.md — Traits bekommen keine eigene Indexzeile.

/**
 * Field flagging. Composed into Stamp.
 */
trait Stamp_Flagging {

	/**
	 * Writes the configured prefixes and added fields into the submission — into
	 * $_POST (what the form builder reads), our copy $request_data, and $gdpr_fields
	 * (what save_message() stores).
	 *
	 * @param array<string|int, mixed> $gdpr_fields The submission's fields, changed in place.
	 * @return void
	 */
	private function flag_spam_fields( &$gdpr_fields ) {
		// Line by line for prefixes
		$lines = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_FLAG_SUFFIXES ), -1, PREG_SPLIT_NO_EMPTY );
		if ( count( $lines ) > 0 ) {
			foreach ( $lines as $line ) {
				// Add the prefix to the respective posted technical field in order to flag this message as spam
				$args = Flag_Prefix::parse_line( $line );
				if ( null !== $args ) {
					$field_link = &$this->access_object_or_array( $gdpr_fields, $args[0] );
					// is_scalar, nicht nur isset: seit Field_Envelopes kann ein Feldname
					// auf eine Struktur zeigen — Prefix davor waere eine Warnung.
					if ( isset( $field_link ) && is_scalar( $field_link ) ) {
						$prefix    = htmlspecialchars( $args[1], ENT_QUOTES, 'UTF-8' );
						$copy_link = &$this->access_object_or_array( $this->request_data, $args[0] );
						$copy_link = is_scalar( $copy_link ) ? $prefix . $copy_link : $copy_link;
						// phpcs:ignore WordPress.Security.NonceVerification.Missing -- writes the flag where the form builder reads; see the file docblock.
						$post_link = &$this->access_object_or_array( $_POST, $args[0] );
						if ( isset( $post_link ) && is_scalar( $post_link ) ) {
							$post_link = $prefix . $post_link;
						} else {
							$this->flag_inside_json( $args[0], $prefix );
						}
						$field_link = $prefix . $field_link;
					}
					unset( $field_link, $copy_link, $post_link );
				}
			}
			$this->print_debug_information( 'Fields flagged' );
		}
		// Line by line for new fields
		$lines = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_FLAG_TAGS ), -1, PREG_SPLIT_NO_EMPTY );
		if ( count( $lines ) > 0 ) {
			foreach ( $lines as $line ) {
				// Add the new field to the _POST array in order to flag this message as spam
				$args = Flag_Prefix::parse_line( $line );
				if ( null !== $args ) {

					$field                        = htmlspecialchars( $args[0], ENT_QUOTES, 'UTF-8' );
					$value                        = htmlspecialchars( $args[1], ENT_QUOTES, 'UTF-8' );
					$_POST[ $field ]              = $value;
					$this->request_data[ $field ] = $value;
					$gdpr_fields[ $field ]        = $value;
				}
			}
			$this->print_debug_information( 'New flag fields added' );
		}
	}

	/**
	 * The prefix for a field that is not a plain $_POST value but sits inside JSON text —
	 * an envelope field (first path segment is the $_POST key holding the text) or a JSON
	 * request body. Any doubt leaves the text as it was (Flag_Prefix returns null).
	 *
	 * @param string $path   The rule's field path, `->`-separated.
	 * @param string $prefix The prefix as it is to appear.
	 * @return void
	 */
	private function flag_inside_json( $path, $prefix ) {
		$segments = explode( Flag_Prefix::PATH_SEPARATOR, $path );
		$root     = $segments[0];
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- see flag_spam_fields().
		if ( count( $segments ) > 1 && isset( $_POST[ $root ] ) && is_string( $_POST[ $root ] ) ) {
			// wp_magic_quotes() has slashed $_POST once `sanitize_comment_cookies` fired
			// (wp-settings.php, right after it). A check at include time sees the raw text,
			// one deferred to a later hook the slashed one — and must hand it back slashed.
			$slashed = did_action( 'sanitize_comment_cookies' ) > 0;
			$text    = $slashed ? wp_unslash( $_POST[ $root ] ) : $_POST[ $root ];
			// Only a field Field_Envelopes really unpacked at capture time, and only while it
			// still holds that very text: never re-encode something that merely looks like
			// JSON, or that someone changed in between.
			if ( ! isset( $this->envelope_raw[ $root ] ) || $this->envelope_raw[ $root ] !== $text ) {
				return;
			}
			$flagged = Flag_Prefix::prefix_in_json( $text, array_slice( $segments, 1 ), $prefix );
			if ( null !== $flagged ) {
				$_POST[ $root ] = $slashed ? wp_slash( $flagged ) : $flagged;
			}
			return;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		// Only a REST request (nobody else reads the global below) whose body was merged
		// whole — a capped body ($body_raw set) never was, see trait-stamp-capture.php.
		if ( null === $this->rest_route || null !== $this->body_raw || ! $this->is_json_body_request() ) {
			return;
		}
		// WP_REST_Server::get_raw_data() reads the body through this global and fills it
		// from php://input only while it is unset — so replacing it is how a prefixed body
		// reaches the REST handler. php://input itself cannot be changed: a builder that
		// reads it directly still gets the unflagged body.
		global $HTTP_RAW_POST_DATA; // phpcs:ignore PHPCompatibility.Variables.RemovedPredefinedGlobalVariables.http_raw_post_dataDeprecatedRemoved -- WordPress core still uses this name as the REST body cache, see above.
		$body    = isset( $HTTP_RAW_POST_DATA ) ? $HTTP_RAW_POST_DATA : (string) file_get_contents( 'php://input' ); // phpcs:ignore PHPCompatibility.Variables.RemovedPredefinedGlobalVariables.http_raw_post_dataDeprecatedRemoved
		$flagged = Flag_Prefix::prefix_in_json( $body, $segments, $prefix );
		if ( null !== $flagged ) {
			$HTTP_RAW_POST_DATA = $flagged; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited, PHPCompatibility.Variables.RemovedPredefinedGlobalVariables.http_raw_post_dataDeprecatedRemoved -- the deliberate hand-over to WP_REST_Server, see above.
		}
	}

	/**
	 * Whether the body is JSON — the same condition capture_request_data() merges it on.
	 *
	 * @return bool
	 */
	private function is_json_body_request() {
		$method       = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against fixed strings only.
		$content_type = isset( $_SERVER['CONTENT_TYPE'] ) && is_string( $_SERVER['CONTENT_TYPE'] ) ? $_SERVER['CONTENT_TYPE'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- searched for one fixed media type only.
		return in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) && false !== strpos( $content_type, 'application/json' );
	}

	/** Resolves a '->'-separated path into a nested array/object and returns a reference to the target value
	 *
	 */
	private function &access_object_or_array( &$obj, $path ) {
		$path_segments  = explode( '->', $path );
		$current_object = &$obj;
		foreach ( $path_segments as $segment ) {
			// If the segment is a numeric key, convert it to an integer
			$segment = is_numeric( $segment ) ? (int) $segment : $segment;

			if ( is_array( $current_object ) && array_key_exists( $segment, $current_object ) ) {
				// If the segment is a valid key in the array, move to the next level
				$current_object = &$current_object[ $segment ];
			} elseif ( is_object( $current_object ) && property_exists( $current_object, $segment ) ) {
				// If the segment is a valid property in the object, move to the next level
				$current_object = &$current_object->$segment;
			} else {
				// A variable, not the literal: returning `null` from a by-reference function
				// raises a notice, and with WP_DEBUG_DISPLAY that lands in front of a REST
				// answer and breaks it (Fable, release plan, finding F1).
				$none = null;
				return $none;
			}
		}
		// Modify the value by adding the prefix
		return $current_object;
	}
}
