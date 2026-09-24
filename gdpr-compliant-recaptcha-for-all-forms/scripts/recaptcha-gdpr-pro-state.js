/**
 * The deactivation feedback dialog on wp-admin's plugins screen.
 *
 * Owned in PHP by Deactivation_Feedback (plugin/includes/class-deactivation-feedback.php),
 * which hands over every string, the endpoint and the plugin version as `gdprDeactivate`.
 * Detail documentation: handbuch/feedback.md.
 *
 * THREE DEFECTS THIS FILE WAS REWRITTEN TO FIX, all of them silent:
 *
 * 1. THE MESSAGE COULD NOT ARRIVE. The old code called xhr.send() and set
 *    window.location.href on the very next line. A navigation cancels an in-flight
 *    XHR, so even with a working receiver the message was a race the sender usually
 *    lost. fetch(..., { keepalive: true }) exists for exactly this situation: the
 *    browser keeps the request alive across the navigation.
 *
 * 2. IT LEAKED THE SITE'S ADMIN URL. A plain cross-origin POST carries the Referer
 *    header, so every submission told the receiving server which wp-admin it came
 *    from — an address that has no business leaving the site, least of all from this
 *    plugin. referrerPolicy: 'no-referrer' ends that.
 *
 * 3. NOBODY WAS TOLD WHERE THE TEXT WENT. The dialog said "give us feedback" and
 *    posted to a third-party host without naming it. The disclosure now sits above
 *    the buttons, and "Deactivate without sending" is a first-class button rather
 *    than something to infer from an empty field.
 *
 * THE ONE RULE THIS FILE MUST NEVER BREAK: deactivating the plugin cannot depend on
 * any of this. Every path — no fetch in the browser, network down, receiver gone,
 * exception halfway through — ends in the navigation the administrator asked for.
 */

( function () {
	'use strict';

	var FALLBACK_MAX_CHARS = 500;

	/**
	 * Cut a message down to what will actually be stored.
	 *
	 * The receiver enforces the same limit; doing it here too means the person sees
	 * what they are sending instead of learning about the cut afterwards.
	 *
	 * @param {string} raw   Whatever is in the textarea.
	 * @param {number} limit Maximum number of characters.
	 * @return {string} Trimmed and capped text.
	 */
	function normalizeText( raw, limit ) {
		var text = typeof raw === 'string' ? raw : '';
		var max = toLimit( limit );

		text = text.replace( /\r\n?/g, '\n' ).trim();

		return text.length > max ? text.slice( 0, max ) : text;
	}

	/**
	 * Read the character limit out of the localized config.
	 *
	 * PARSES A STRING ON PURPOSE. wp_localize_script() casts every scalar it is handed
	 * to a string before printing it, so PHP's `int 500` arrives here as `'500'`. A
	 * `typeof limit === 'number'` check therefore never matched, and the limit silently
	 * fell back to 500 — which happened to be the same number, so nothing looked wrong.
	 * Changing MAX_CHARS in PHP would have had no effect at all. Found by running the
	 * real thing in wp-env; no unit test would have shown it, because the test passed
	 * the number the PHP side never sends.
	 *
	 * @param {*} value Whatever `maxChars` turned out to be.
	 * @return {number} A usable positive limit.
	 */
	function toLimit( value ) {
		var parsed = parseInt( value, 10 );

		return isFinite( parsed ) && parsed > 0 ? parsed : FALLBACK_MAX_CHARS;
	}

	/**
	 * Whether there is anything worth transmitting.
	 *
	 * The single gate in front of the only outbound request this plugin makes. An
	 * empty or whitespace-only box is not a submission, it is a person who wants to
	 * deactivate — see the class docblock in PHP.
	 *
	 * @param {string} text Normalized message.
	 * @return {boolean} True when a request should be made at all.
	 */
	function shouldSend( text ) {
		return typeof text === 'string' && '' !== text;
	}

	/**
	 * The fields that go on the wire.
	 *
	 * `grp_reason_long` is the historical field name and must stay: installations
	 * running older versions of this plugin post the same name, and the receiver
	 * accepts one shape, not two.
	 *
	 * @param {string} text   Normalized message.
	 * @param {Object} config Localized `gdprDeactivate` data.
	 * @return {Object} Flat map of field name to value.
	 */
	function payloadFields( text, config ) {
		var settings = config || {};
		var fields = { grp_reason_long: text };

		// Only sent from this version on. An entry without them is from the installed
		// base and cannot be attributed to a plugin — known, and preferable to
		// deriving it from Origin or Referer, which is the one thing not to send.
		if ( settings.plugin ) {
			fields.plugin = settings.plugin;
		}
		if ( settings.version ) {
			fields.plugin_version = settings.version;
		}

		return fields;
	}

	/**
	 * The fetch options, without the body.
	 *
	 * Split out from the call so the two properties that carry the whole privacy
	 * argument — `referrerPolicy` and `keepalive` — can be asserted in a test instead
	 * of being noticed missing by nobody, which is how they came to be missing in the
	 * first place.
	 *
	 * @return {Object} Options for fetch().
	 */
	function requestOptions() {
		return {
			method: 'POST',
			mode: 'no-cors',
			cache: 'no-store',
			credentials: 'omit',
			referrerPolicy: 'no-referrer',
			keepalive: true
		};
	}

	/**
	 * Fire the request and forget it.
	 *
	 * Deliberately returns nothing and swallows every error: the caller navigates
	 * immediately afterwards, and there is no state in which telling the
	 * administrator that their farewell note failed to send would help them.
	 *
	 * @param {string} text   Normalized message.
	 * @param {Object} config Localized `gdprDeactivate` data.
	 * @return {void}
	 */
	function send( text, config ) {
		var settings = config || {};

		if ( ! settings.endpoint || typeof window.fetch !== 'function' || typeof window.FormData !== 'function' ) {
			return;
		}

		try {
			var fields = payloadFields( text, settings );
			var body = new window.FormData();

			Object.keys( fields ).forEach( function ( name ) {
				body.append( name, fields[ name ] );
			} );

			var options = requestOptions();
			options.body = body;

			window.fetch( settings.endpoint, options ).catch( function () {} );
		} catch ( e ) {
			// Intentionally empty — see the docblock.
		}
	}

	/**
	 * Build the dialog.
	 *
	 * @param {Object}   config  Localized `gdprDeactivate` data.
	 * @param {Function} onClose Called with the entered text, or null when cancelled.
	 * @return {HTMLElement} The overlay, not yet attached.
	 */
	function buildDialog( config, onClose ) {
		var overlay = document.createElement( 'div' );
		overlay.className = 'gdpr-deactivate-overlay';

		var box = document.createElement( 'div' );
		box.className = 'gdpr-deactivate-box';
		box.setAttribute( 'role', 'dialog' );
		box.setAttribute( 'aria-modal', 'true' );
		box.setAttribute( 'aria-labelledby', 'gdpr-deactivate-heading' );

		var heading = document.createElement( 'h2' );
		heading.id = 'gdpr-deactivate-heading';
		heading.textContent = config.heading || '';

		var intro = document.createElement( 'p' );
		intro.className = 'gdpr-deactivate-intro';
		intro.textContent = config.intro || '';

		var label = document.createElement( 'label' );
		label.className = 'gdpr-deactivate-label';
		label.setAttribute( 'for', 'grp_reason_long' );
		label.textContent = config.label || '';

		var textarea = document.createElement( 'textarea' );
		textarea.id = 'grp_reason_long';
		textarea.name = 'grp_reason_long';
		textarea.rows = 5;
		textarea.maxLength = toLimit( config.maxChars );

		var notice = document.createElement( 'p' );
		notice.className = 'gdpr-deactivate-notice';
		notice.textContent = config.notice || '';

		if ( config.privacy ) {
			notice.appendChild( document.createTextNode( ' ' ) );
			var link = document.createElement( 'a' );
			link.href = config.privacy;
			link.target = '_blank';
			link.rel = 'noopener noreferrer';
			link.textContent = config.privacyOf || config.privacy;
			notice.appendChild( link );
		}

		var actions = document.createElement( 'p' );
		actions.className = 'gdpr-deactivate-actions';

		var sendButton = document.createElement( 'button' );
		sendButton.type = 'button';
		sendButton.className = 'button button-primary';
		sendButton.textContent = config.send || '';

		var skipButton = document.createElement( 'button' );
		skipButton.type = 'button';
		skipButton.className = 'button';
		skipButton.textContent = config.skip || '';

		var cancelButton = document.createElement( 'button' );
		cancelButton.type = 'button';
		cancelButton.className = 'button-link gdpr-deactivate-cancel';
		cancelButton.textContent = config.cancel || '';

		sendButton.addEventListener( 'click', function () {
			onClose( normalizeText( textarea.value, config.maxChars ) );
		} );
		skipButton.addEventListener( 'click', function () {
			onClose( '' );
		} );
		cancelButton.addEventListener( 'click', function () {
			onClose( null );
		} );

		actions.appendChild( sendButton );
		actions.appendChild( skipButton );
		actions.appendChild( cancelButton );

		box.appendChild( heading );
		box.appendChild( intro );
		box.appendChild( label );
		box.appendChild( textarea );
		box.appendChild( notice );
		box.appendChild( actions );
		overlay.appendChild( box );

		overlay.addEventListener( 'keydown', function ( event ) {
			if ( 'Escape' === event.key ) {
				onClose( null );
			}
		} );

		return overlay;
	}

	/**
	 * Wire the dialog in front of this plugin's deactivate link.
	 *
	 * @return {void}
	 */
	function init() {
		var config = window.gdprDeactivate;

		if ( ! config || ! config.slug ) {
			return;
		}

		var link = document.querySelector( '[data-slug="' + config.slug + '"] .deactivate a' );

		if ( ! link ) {
			return;
		}

		link.addEventListener( 'click', function ( event ) {
			event.preventDefault();

			var target = link.getAttribute( 'href' );
			var overlay = buildDialog( config, function ( text ) {
				if ( overlay.parentNode ) {
					overlay.parentNode.removeChild( overlay );
				}

				// null means "cancel" — stay on the page, deactivate nothing.
				if ( null === text ) {
					return;
				}

				if ( shouldSend( text ) ) {
					send( text, config );
				}

				window.location.href = target;
			} );

			document.body.appendChild( overlay );

			var textarea = overlay.querySelector( 'textarea' );
			if ( textarea ) {
				textarea.focus();
			}
		}, { capture: true } );
	}

	if ( typeof document !== 'undefined' ) {
		if ( 'loading' === document.readyState ) {
			document.addEventListener( 'DOMContentLoaded', init );
		} else {
			init();
		}
	}

	// Expose the pure, DOM-independent helpers for the Node-based regression tests
	// (tests/js/, run via `node --test`). No effect in the browser: `module` is
	// undefined there, so this block is skipped — same idiom as
	// plugin/scripts/recaptcha-gdpr-pow.js.
	if ( typeof module !== 'undefined' && module.exports ) {
		module.exports = {
			normalizeText: normalizeText,
			toLimit: toLimit,
			shouldSend: shouldSend,
			payloadFields: payloadFields,
			requestOptions: requestOptions
		};
	}
}() );
