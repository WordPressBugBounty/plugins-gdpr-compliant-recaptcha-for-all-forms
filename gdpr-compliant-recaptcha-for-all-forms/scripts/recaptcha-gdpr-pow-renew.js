/**
 * Keeps the proof-of-work token fresh when timers do not run (handbuch/pow-renew.md).
 *
 * A token is valid for (time window + 2) minutes after get_stamp issued it
 * (StampToken::verify_integrity()). recaptcha-gdpr-pow.js used to renew it only with
 * setInterval. Android freezes timers while the screen is locked or the tab is in the
 * background, so a visitor who filled a long form for 12-16 minutes sent an expired token
 * and got a 422 (no_pow:invalid_token). Nothing looked at the token's age on submit.
 *
 * This file only decides WHEN the existing initCaptcha() runs, measured with Date.now()
 * (wall clock, keeps running while timers are frozen), never by counting timer ticks:
 *   - a timer due at the end of the time window after the token's issue (2 minutes before
 *     it expires) — the old interval's cadence, so no extra load;
 *   - visibilitychange (visible), pageshow (also from the back/forward cache) and focus:
 *     renew at once if the token is that old or missing. A fresh token does nothing;
 *   - submit, and same-origin POSTs through fetch: only when the token is missing or about
 *     to expire, renew first, then send — capped, after HOLD_MAX_MS it sends anyway;
 *   - typing in a form (keydown, input): renew at once if the token is that old or missing.
 *     A builder that sends on Enter straight through XHR (JetFormBuilder) fires no submit
 *     event to hold, so the renewal has to be under way already. A fresh token does nothing.
 * Never two renewals at once from these triggers. It touches neither the PoW maths nor
 * any server-side check.
 *
 * Enqueued just BEFORE recaptcha-gdpr-pow.js (Stamp::add_script_to_header()), by order and
 * deliberately not as its dependency: a missing dependency would make WordPress drop the
 * PoW script too. Before recaptcha-gdpr-pow.js calls install() at its start, only the
 * early start below listens. Without this file (an old cached page, an asset manager that
 * dropped it) the old setInterval renew runs, and the start waits for `load`.
 *
 * Start at DOMContentLoaded (handbuch/pow-renew.md "Start ab DOMContentLoaded"): on its
 * own recaptcha-gdpr-pow.js starts at `load`, which waits for every image, iframe and ad.
 * With this file it starts as soon as the HTML is parsed. Fetch/XHR are then wrapped
 * before scripts that only arrive until `load` (async ones); one that replaces fetch or
 * XHR without handing on to us would cut the token out of its requests. So once after
 * `load`, rewrapLate() wraps whatever replaced ours once more, token only.
 *
 * Early start (handbuch/pow-renew.md "Absenden vor load"): a form sent before the start
 * navigates away, the navigation aborts the page load, and `load` never comes: the
 * submission went out without a token and without any solve the server's 5-second row
 * poll could wait for — 422 no_pow:no_token every time (measured on wp-login.php, user
 * report 2026-11: a login link opened in an in-app browser). So while the page is still
 * loading, a POST submit or a press/key in a form starts it at once — before
 * DOMContentLoaded too, which waits for every deferred script. The old page keeps running
 * until the answer arrives and solves while the server waits.
 */
var gdpr_compliant_recaptcha_renew = {
	// Hold a submission when less than this is left of the token's life. Covers the trip to
	// the server, a slow upload included: the server checks the age when PHP starts.
	HOLD_MARGIN_MS : 60000,
	// Longest hold. Afterwards the submission goes out anyway, and the server's 5-second
	// row poll can still catch the renewal through the address path. Never block.
	HOLD_MAX_MS : 8000,
	// A renewal counts as running for at most this long, so a lost one (network gone,
	// page frozen mid-solve) never stops the next. Long enough for a slow solve under attack.
	IN_FLIGHT_MAX_MS : 120000,
	// The timer never fires more often than once a minute.
	MIN_DELAY_MS : 60000,

	issuedAt : null,  // Date.now() when the get_stamp request of the published token went out
	startedAt : null, // Date.now() when the latest renewal started; null once one is published
	timer : null,
	waiters : [],
	heldForms : [], // every form held right now, each with its own HOLD_MAX_MS (release())
	releasing : null,
	waitedOut : null, // the token a hold already waited HOLD_MAX_MS for in vain: never held again
	core : null,
	getToken : null,
	installed : false,
	own : null, // fetch and XHR open/send as the start left them; see rewrapLate()

	// --- pure: no DOM, no globals; pinned by tests/js/pow-renew.test.js -----------------

	// Mirrors StampToken::verify_integrity(): (max(1, window) + 2) minutes. Only a missing
	// value (gdprPow not localized) falls back to the option default 10.
	lifetimeMs : function ( rawTimeout ) {
		var minutes = ( undefined === rawTimeout || null === rawTimeout ) ? 10 : Math.max( 1, parseInt( rawTimeout, 10 ) || 0 );
		return ( minutes + 2 ) * 60000;
	},

	// Due for renewal at the end of the time window, i.e. 2 minutes before expiry (83 % at
	// the default 10 minutes). At least 1 minute.
	renewAfterMs : function ( rawTimeout ) {
		return gdpr_compliant_recaptcha_renew.lifetimeMs( rawTimeout ) - 2 * 60000;
	},

	// A clock that went backwards counts as old: renewing costs one request, guessing wrong a block.
	isStale : function ( issuedAt, now, rawTimeout ) {
		if ( null === issuedAt || undefined === issuedAt ) {
			return true;
		}
		var age = now - issuedAt;
		return age < 0 || age >= gdpr_compliant_recaptcha_renew.renewAfterMs( rawTimeout );
	},

	// Whether a submission must wait for a new token. Without a token nothing is held: that
	// case stays as before (the server's row poll waits for the running solve).
	isNearlyExpired : function ( issuedAt, now, rawTimeout ) {
		if ( null === issuedAt || undefined === issuedAt ) {
			return false;
		}
		var age = now - issuedAt;
		return age < 0 || age >= gdpr_compliant_recaptcha_renew.lifetimeMs( rawTimeout ) - gdpr_compliant_recaptcha_renew.HOLD_MARGIN_MS;
	},

	isInFlight : function ( startedAt, now ) {
		if ( null === startedAt || undefined === startedAt ) {
			return false;
		}
		var running = now - startedAt;
		return running >= 0 && running < gdpr_compliant_recaptcha_renew.IN_FLIGHT_MAX_MS;
	},

	// s = { hasToken, issuedAt, startedAt, now, rawTimeout }
	shouldRenew : function ( s ) {
		var R = gdpr_compliant_recaptcha_renew;
		return ( ! s.hasToken || R.isStale( s.issuedAt, s.now, s.rawTimeout ) ) && ! R.isInFlight( s.startedAt, s.now );
	},

	// s = { hasToken, token, waitedOut, issuedAt, now, rawTimeout, canResend, defaultPrevented }
	// Once a hold waited HOLD_MAX_MS in vain for this token, nothing waits for it again: a
	// form released after its cap and sent by its builder through fetch would otherwise wait
	// a second time (up to twice HOLD_MAX_MS). Rather send than wait.
	shouldHold : function ( s ) {
		return !! ( s.hasToken && s.canResend && ! s.defaultPrevented
			&& ! ( s.waitedOut && s.token === s.waitedOut )
			&& gdpr_compliant_recaptcha_renew.isNearlyExpired( s.issuedAt, s.now, s.rawTimeout ) );
	},

	// Delay until the next timer check: the rest of the window, at least MIN_DELAY_MS.
	nextCheckMs : function ( issuedAt, now, rawTimeout ) {
		var R = gdpr_compliant_recaptcha_renew;
		var age = ( null === issuedAt || undefined === issuedAt ) ? 0 : now - issuedAt;
		var rest = age < 0 ? 0 : R.renewAfterMs( rawTimeout ) - age;
		return Math.max( R.MIN_DELAY_MS, rest );
	},

	// A held fetch body may already carry the old token (built from the form's hidden
	// field). Swap it for the new one; the token is 100 alphanumeric characters, so a
	// plain replace cannot hit anything else. Unknown body shapes stay untouched.
	swapToken : function ( body, oldToken, newToken ) {
		if ( ! oldToken || ! newToken || oldToken === newToken ) {
			return body;
		}
		if ( typeof body === 'string' ) {
			return body.split( oldToken ).join( newToken );
		}
		var brand = ( body && typeof body === 'object' ) ? Object.prototype.toString.call( body ).slice( 8, -1 ) : '';
		if ( ( 'FormData' === brand || 'URLSearchParams' === brand ) && 'function' === typeof body.get && 'function' === typeof body.set ) {
			if ( body.get( 'gdpr_pow_token' ) === oldToken ) {
				body.set( 'gdpr_pow_token', newToken );
			}
		}
		return body;
	},

	// Early start, before `load`: s = { started, type, postForm, inForm }. A submit counts only
	// for a POST form (a GET form carries no token); a press or key only inside a form.
	shouldStartEarly : function ( s ) {
		if ( s.started ) {
			return false;
		}
		return !! ( 'submit' === s.type ? s.postForm : s.inForm );
	},

	// Whether a URL points at this site. Only those carry a token the server checks.
	isSameOrigin : function ( url, here ) {
		try {
			var raw = ( url && typeof url === 'object' && typeof url.url === 'string' ) ? url.url : String( url );
			return new URL( raw, here.href ).origin === here.origin;
		} catch ( e ) {
			return false;
		}
	},

	// --- wiring -------------------------------------------------------------------------

	rawTimeout : function () {
		return ( typeof gdprPow !== 'undefined' && gdprPow ) ? gdprPow.timeout : undefined;
	},

	state : function () {
		var R = gdpr_compliant_recaptcha_renew;
		var token = R.getToken();
		return {
			hasToken : !! token,
			token : token,
			waitedOut : R.waitedOut,
			issuedAt : R.issuedAt,
			startedAt : R.startedAt,
			now : Date.now(),
			rawTimeout : R.rawTimeout(),
		};
	},

	// Called by recaptcha-gdpr-pow.js once, at its start. Returns true, so the caller skips
	// its old setInterval.
	install : function ( core, getToken ) {
		var R = gdpr_compliant_recaptcha_renew;
		if ( R.installed ) {
			return true;
		}
		R.installed = true;
		R.core = core;
		R.getToken = getToken;
		R.stopEarlyStart( document );
		document.addEventListener( 'visibilitychange', function () {
			if ( 'hidden' !== document.visibilityState ) {
				R.kick();
			}
		} );
		window.addEventListener( 'pageshow', function () { R.kick(); } );
		window.addEventListener( 'focus', function () { R.kick(); } );
		document.addEventListener( 'submit', R.onSubmit, true );
		R.KEY_EVENTS.forEach( function ( type ) {
			document.addEventListener( type, R.onFormKey, { capture : true, passive : true } );
		} );
		R.wrapFetch();
		R.arm( R.renewAfterMs( R.rawTimeout() ) );
		R.own = R.currentWrappers();
		if ( 'complete' !== document.readyState ) {
			// A tick after `load`, so a replacement made in another `load` listener counts too.
			window.addEventListener( 'load', function () { setTimeout( R.rewrapLate, 0 ); }, { once : true } );
		}
		return true;
	},

	currentWrappers : function () {
		var proto = ( typeof XMLHttpRequest !== 'undefined' ) ? XMLHttpRequest.prototype : {};
		return { fetch : window.fetch, open : proto.open, send : proto.send };
	},

	// Started before `load`: a script that came later (async, or from a `load` listener) may
	// have replaced fetch or XHR. Delegating to ours or not cannot be told from outside, so
	// whatever replaced ours is wrapped once more: the token goes into POST bodies, and a
	// renewal follows, like in addFirstStamp(). Once, only what changed, nothing else: no
	// response handling (a delegating replacement would show a block message twice), no
	// second hold (two holds in a row could wait twice HOLD_MAX_MS). The token injection
	// is idempotent, so a request through both layers carries it once.
	rewrapLate : function () {
		var R = gdpr_compliant_recaptcha_renew;
		var core = R.core;
		var now = R.currentWrappers();
		if ( ! core || ! R.own ) {
			return;
		}
		var postsTo = function ( method, url, body ) {
			return !! method && 'POST' === String( method ).toUpperCase() && ! core.isPluginCall( url, body );
		};
		if ( 'function' === typeof now.fetch && now.fetch !== R.own.fetch ) {
			var fetchNow = now.fetch;
			window.fetch = function ( input, init ) {
				var post = !! init && 'body' in init && postsTo( init.method, input, init.body );
				if ( post ) {
					init.body = core.injectTokenIntoBody( init.body );
				}
				var result = fetchNow.apply( this, arguments );
				if ( post && result && 'function' === typeof result.then ) {
					result.then( function () { core.scheduleRenew(); }, function () {} );
				}
				return result;
			};
		}
		var proto = ( typeof XMLHttpRequest !== 'undefined' ) ? XMLHttpRequest.prototype : null;
		if ( proto && 'function' === typeof now.open && now.open !== R.own.open ) {
			proto.open = function ( method, url ) {
				this._method = method;
				this._url = url;
				return now.open.apply( this, arguments );
			};
		}
		if ( proto && 'function' === typeof now.send && now.send !== R.own.send ) {
			proto.send = function ( data ) {
				var args = Array.prototype.slice.call( arguments );
				if ( postsTo( this._method, this._url, data ) ) {
					args[ 0 ] = core.injectTokenIntoBody( data );
					if ( 'function' === typeof this.addEventListener ) {
						this.addEventListener( 'loadend', function () { core.scheduleRenew(); } );
					}
				}
				return now.send.apply( this, args );
			};
		}
		R.own = R.currentWrappers();
	},

	EARLY_EVENTS : [ 'submit', 'pointerdown', 'keydown' ],

	// Typing in a form, after install(). Capture phase on document, so it runs before a
	// builder's own keydown handler on the field sends the form (JetFormBuilder: Enter ->
	// XHR, no submit event, nothing to hold). Not held either: the request leaves with the
	// old token, and the server's 5-second row poll catches the renewal started here
	// through the address path (handbuch/pow-renew.md "Tippen im Formular").
	KEY_EVENTS : [ 'keydown', 'input' ],

	onFormKey : function ( e ) {
		var R = gdpr_compliant_recaptcha_renew;
		if ( R.core && R.core.isFormInteraction( e && e.target ) ) {
			R.kick();
		}
	},

	// Registered at parse time while the page is still loading; install() removes them.
	listenEarlyStart : function ( doc ) {
		gdpr_compliant_recaptcha_renew.EARLY_EVENTS.forEach( function ( type ) {
			doc.addEventListener( type, gdpr_compliant_recaptcha_renew.earlyStart, { capture : true, passive : true } );
		} );
	},

	stopEarlyStart : function ( doc ) {
		if ( doc && 'function' === typeof doc.removeEventListener ) {
			gdpr_compliant_recaptcha_renew.EARLY_EVENTS.forEach( function ( type ) {
				doc.removeEventListener( type, gdpr_compliant_recaptcha_renew.earlyStart, true );
			} );
		}
	},

	// DOMContentLoaded: start recaptcha-gdpr-pow.js now instead of at `load` (file head).
	// Not urgent: the solve runs in slices, the page stays responsive.
	startOnDomReady : function () {
		var core = ( typeof gdpr_compliant_recaptcha !== 'undefined' ) ? gdpr_compliant_recaptcha : null;
		if ( core && ! core.stampLoaded ) {
			core.addFirstStamp();
		}
	},

	// Starts recaptcha-gdpr-pow.js now instead of at `load` (see the file head). Urgent:
	// no token is out, so the solve runs in one piece, as after a form interaction.
	earlyStart : function ( e ) {
		var core = ( typeof gdpr_compliant_recaptcha !== 'undefined' ) ? gdpr_compliant_recaptcha : null;
		var target = e && e.target;
		if ( ! core || ! gdpr_compliant_recaptcha_renew.shouldStartEarly( {
			started : core.stampLoaded,
			type : e.type,
			postForm : !! ( target && 'FORM' === target.tagName && ! core.isGetForm( target ) ),
			inForm : core.isFormInteraction( target ),
		} ) ) {
			return;
		}
		core.solveUrgent = true;
		core.addFirstStamp();
	},

	// recaptcha-gdpr-pow.js: initCaptcha() started a renewal (get_stamp goes out now).
	solveStarted : function ( at ) {
		gdpr_compliant_recaptcha_renew.startedAt = at;
	},

	// recaptcha-gdpr-pow.js: a token was confirmed by check_stamp and published.
	published : function ( issuedAt ) {
		var R = gdpr_compliant_recaptcha_renew;
		R.issuedAt = issuedAt;
		R.startedAt = null;
		R.waitedOut = null;
		if ( R.installed ) {
			R.arm( R.nextCheckMs( issuedAt, Date.now(), R.rawTimeout() ) );
		}
		var waiting = R.waiters;
		R.waiters = [];
		waiting.forEach( function ( done ) { done(); } );
	},

	// Renew if the token is old or missing and no renewal is running. True if it started one.
	kick : function () {
		var R = gdpr_compliant_recaptcha_renew;
		if ( ! R.installed || ! R.shouldRenew( R.state() ) ) {
			return false;
		}
		R.core.initCaptcha();
		// If this renewal fails, the timer tries again one window later, as the interval did.
		R.arm( R.renewAfterMs( R.rawTimeout() ) );
		return true;
	},

	arm : function ( ms ) {
		var R = gdpr_compliant_recaptcha_renew;
		if ( R.timer ) {
			clearTimeout( R.timer );
		}
		R.timer = setTimeout( R.onTimer, ms );
	},

	onTimer : function () {
		var R = gdpr_compliant_recaptcha_renew;
		R.timer = null;
		if ( ! R.kick() ) {
			R.arm( R.nextCheckMs( R.issuedAt, Date.now(), R.rawTimeout() ) );
		}
	},

	// Calls done() once: when the next token is published, or after HOLD_MAX_MS. In the
	// second case the token still out is marked as waited for (shouldHold()).
	whenRenewed : function ( done ) {
		var R = gdpr_compliant_recaptcha_renew;
		var called = false;
		var once = function () {
			if ( ! called ) {
				called = true;
				done();
			}
		};
		R.waiters.push( once );
		setTimeout( function () {
			if ( ! called ) {
				R.waitedOut = R.getToken();
			}
			once();
		}, R.HOLD_MAX_MS );
	},

	// Capturing submit listener. Passes everything untouched unless the token is about to
	// expire; then it holds THIS submission until a new token is out and sends it again
	// with requestSubmit(), which runs the form's own submit handlers (Ajax builders too).
	onSubmit : function ( e ) {
		var R = gdpr_compliant_recaptcha_renew;
		var form = e.target;
		if ( ! form || 'FORM' !== form.tagName || R.core.isGetForm( form ) || form === R.releasing ) {
			return;
		}
		if ( -1 !== R.heldForms.indexOf( form ) ) {
			// A second click on this form while held: its submission goes out once, not twice.
			e.preventDefault();
			e.stopImmediatePropagation();
			return;
		}
		var s = R.state();
		s.canResend = 'function' === typeof form.requestSubmit;
		s.defaultPrevented = !! e.defaultPrevented;
		R.kick();
		if ( ! R.shouldHold( s ) ) {
			return;
		}
		e.preventDefault();
		e.stopImmediatePropagation();
		// Its own entry and its own cap: a second form sent meanwhile is held beside it, and
		// both go out (one slot lost the first form for good).
		R.heldForms.push( form );
		var submitter = ( e.submitter && e.submitter.form === form ) ? e.submitter : null;
		R.whenRenewed( function () {
			R.release( form, submitter );
		} );
	},

	release : function ( form, submitter ) {
		var R = gdpr_compliant_recaptcha_renew;
		var i = R.heldForms.indexOf( form );
		if ( -1 === i ) {
			return;
		}
		R.heldForms.splice( i, 1 );
		R.releasing = form;
		try {
			R.core.updateFormTokenFields( R.getToken() );
			try {
				form.requestSubmit( submitter || undefined );
			} catch ( err ) {
				form.requestSubmit();
			}
		} catch ( err ) {
			if ( typeof console !== 'undefined' && console.warn ) {
				console.warn( 'gdpr-recaptcha: could not resend the held form', err );
			}
		} finally {
			R.releasing = null;
		}
	},

	// Outermost fetch wrapper: a same-origin POST while the token is about to expire waits
	// for the new one (at most HOLD_MAX_MS). Plugin calls and keepalive requests (sent
	// while the page unloads) never wait, nor a token a hold already waited out (a form
	// released after its cap, sent on by its builder through fetch). Everything else passes
	// straight through.
	wrapFetch : function () {
		var R = gdpr_compliant_recaptcha_renew;
		var inner = window.fetch;
		if ( 'function' !== typeof inner ) {
			return;
		}
		window.fetch = function ( input, init ) {
			var method = ( init && init.method ) ? String( init.method ).toUpperCase() : 'GET';
			var oldToken = R.getToken();
			var s = R.state();
			s.canResend = true;
			s.defaultPrevented = false;
			if ( 'POST' !== method || ( init && init.keepalive ) || R.core.isPluginCall( input, init && init.body )
				|| ! R.isSameOrigin( input, window.location ) || ! R.shouldHold( s ) ) {
				return inner.apply( this, arguments );
			}
			var self = this;
			var args = arguments;
			R.kick();
			return new Promise( function ( resolve ) {
				R.whenRenewed( resolve );
			} ).then( function () {
				if ( init && 'body' in init ) {
					init.body = R.swapToken( init.body, oldToken, R.getToken() );
				}
				return inner.apply( self, args );
			} );
		};
	},
};

// Start at DOMContentLoaded, and the early start, only while the page is still loading
// (once it has, recaptcha-gdpr-pow.js starts at once). Run after DOMContentLoaded (injected
// late), the listener never fires and the start waits for `load`, as without this file.
if ( typeof document !== 'undefined' && document && 'complete' !== document.readyState && 'function' === typeof document.addEventListener ) {
	gdpr_compliant_recaptcha_renew.listenEarlyStart( document );
	document.addEventListener( 'DOMContentLoaded', gdpr_compliant_recaptcha_renew.startOnDomReady, { once : true } );
}

// Expose the pure helpers (and the object, for the wiring tests) to tests/js. No effect
// in the browser: `module` is undefined there.
if ( typeof module !== 'undefined' && module.exports ) {
	module.exports = gdpr_compliant_recaptcha_renew;
}
