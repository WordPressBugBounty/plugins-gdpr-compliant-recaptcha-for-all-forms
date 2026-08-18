/**
 * Direct-analysis-mode frontend overlay: lets an admin capture not-yet-covered form
 * submissions and add recognition patterns/actions live from the page.
 *
 * Enqueued + localized by Analysis::add_javascript() as the global `gdprAnalysis`
 * ( { ajaxUrl, storeNonce, i18n:{…} } ). Only loaded when POW_DIRECT_ANALYSIS_MODE is on
 * and the current user can manage_options. Object literal `gdpr_compliant_recaptcha_analysis`.
 *
 * Persistence: captured entries no longer survive page navigation via a client-side
 * mechanism (no cookies/localStorage/URL-parameters — Art. 5(3) ePrivacy stays out of
 * scope for this admin-only overlay). Instead, every captured/updated entry is
 * persisted server-side via persistEntry()
 * (admin-ajax action `gdpr_analysis_store`, see Analysis::store_analysis_entry()) and
 * re-fetched on load via restoreEntries() (`gdpr_analysis_restore`).
 *
 * This file holds the object DECLARATION plus the pure, DOM- and network-free helpers;
 * the rest of the overlay lives in four sibling modules (…-model, …-ui, …-guide,
 * …-capture) that extend the same object. stripPluginFields() and isPasswordKey() stay
 * HERE on purpose: both are pinned against their server-side twins by tests that read
 * this file by name (StampStripPluginFieldsTest, CredentialFieldsTest) — moving either
 * would make those source-level twin checks silently match nothing.
 *
 * Load order is enforced by the wp_enqueue_script() dependency chain in
 * Analysis::add_javascript() — there is no bundler in this plugin and none is being
 * introduced. The chain is linear and total:
 *
 *   gdpr-recaptcha-analysis          (this object literal + the pure helpers)
 *     -> gdpr-recaptcha-analysis-model
 *       -> gdpr-recaptcha-analysis-ui
 *         -> gdpr-recaptcha-analysis-guide
 *           -> gdpr-recaptcha-analysis-capture   (also registers the window 'load' hook)
 *
 * Every module beyond this file extends the SAME object via Object.assign() — one
 * global, one namespace, unchanged call sites (everything still reads
 * gdpr_compliant_recaptcha_analysis.foo()). Cross-module calls only ever happen at
 * RUNTIME (after the load event), never during evaluation, so only the object's
 * assembly order matters, and the dependency chain fixes that.
 */
var gdpr_compliant_recaptcha_analysis = {
	idCounter : 0,
	jsonArray : [],
	patterns : [],
	actions : [],
	routes : [],
	currentName : '',
	persistDebounceTimers : {},
	// typeof guards keep the object literal evaluable outside a browser too (the
	// Node-based regression tests, tests/js/, require this file for its pure helpers —
	// same pattern as recaptcha-gdpr-pow.js's originalXhrOpen/originalFetch) — in the
	// browser these globals always exist, so behaviour there is unchanged.
	originalXhrOpen : ( typeof XMLHttpRequest !== 'undefined' ) ? XMLHttpRequest.prototype.open : null,
	originalXhrSend : ( typeof XMLHttpRequest !== 'undefined' ) ? XMLHttpRequest.prototype.send : null,
	originalFetch : ( typeof window !== 'undefined' ) ? window.fetch : null,//.bind(window),
	/** Remove the plugin's OWN injected fields from a captured submission before it is
	 * analyzed/persisted. Security-relevant, not cosmetic: a recognition pattern saved
	 * from a capture that includes e.g. `gdpr_pow_token` would only match POSTs that
	 * CARRY the token — a bot simply omitting the field would fall out of the pattern
	 * and thus out of the spam check entirely. Plugin-injected fields must never become
	 * part of a pattern (they are also useless as a display name — seekName() would
	 * otherwise label form entries "gdpr_pow_token").
	 */
	stripPluginFields : function(jsonData) {
		if (jsonData && typeof jsonData === 'object') {
			delete jsonData['gdpr_pow_token'];
			delete jsonData['hashPWFields'];
		}
		return jsonData;
	},
	/** Delete the value at the given key path (array of segments) from a nested object. */
	removeByPath : function(obj, segments) {
		if (!obj || typeof obj !== 'object' || !segments || !segments.length) {
			return;
		}
		if (segments.length === 1) {
			delete obj[segments[0]];
			return;
		}
		gdpr_compliant_recaptcha_analysis.removeByPath(obj[segments[0]], segments.slice(1));
	},
	/** The plugin's OWN ajax actions. Client-side twin of the server's
	 * excluded_actions_for_analysis (Stamp::save_for_analysis): the PoW client posts
	 * get_stamp/check_stamp through the very fetch/XHR interceptors this overlay
	 * installs — without this guard the plugin's own traffic shows up as a capturable
	 * "form" (and saving it as an action would make the spam check monitor itself).
	 */
	isOwnPluginAction : function(jsonData) {
		return !!jsonData && typeof jsonData === 'object'
			&& ['get_stamp', 'check_stamp', 'gdpr_analysis_store', 'gdpr_analysis_restore', 'save_pattern_frontend'].includes(jsonData.action);
	},
	/**
	 * Client-side twin of RestRoute::extract() (class-rest-route.php) — REST_ROUTES_PLAN.md
	 * AP5. Deliberately a SIMPLER mirror, not a security boundary (unlike the server
	 * class, which decides whether a submission gets spam-checked): this only feeds the
	 * "covered"/"not covered" hint in the analysis overlay, so it only needs the two
	 * spellings a REST-calling fetch()/XHR request actually uses — the `rest_route` query
	 * parameter (plain permalinks) and the REST-prefix path segment (pretty permalinks,
	 * gdprAnalysis.restPrefix = `rest_get_url_prefix()`, never hardcode 'wp-json'). The
	 * server-only `rest_route` POST-BODY spelling has no client-JS equivalent to mirror —
	 * a fetch()/XHR call never disguises its own target URL that way.
	 *
	 * @param {string} url Absolute or relative URL, as passed to fetch()/XHR.open().
	 * @param {string} [prefix] REST prefix override — used by the Node tests; production
	 *   callers omit it and fall back to the localized gdprAnalysis.restPrefix.
	 * @returns {string|null} Canonical route ('/namespace/version/…'), or null.
	 */
	extractRestRoute : function(url, prefix) {
		if (typeof url !== 'string' || '' === url) {
			return null;
		}
		var base = (typeof window !== 'undefined' && window.location) ? window.location.href : 'http://gdpr-analysis.invalid/';
		var absolute;
		try {
			absolute = new URL(url, base);
		} catch (e) {
			return null;
		}
		// Plain permalinks: the route travels as the `rest_route` query parameter.
		var restRouteParam = absolute.searchParams.get('rest_route');
		if (restRouteParam) {
			var paramSegments = restRouteParam.split('/').filter(Boolean);
			return paramSegments.length ? '/' + paramSegments.join('/') : null;
		}
		// Pretty permalinks: the route is baked into the path, prefixed by the REST prefix.
		var restPrefix = (typeof prefix === 'string' && prefix)
			? prefix
			: ((typeof gdprAnalysis !== 'undefined' && gdprAnalysis && gdprAnalysis.restPrefix) || '');
		if (!restPrefix) {
			return null;
		}
		var pathSegments = absolute.pathname.split('/').filter(Boolean);
		var prefixSegments = restPrefix.split('/').filter(Boolean);
		if (!prefixSegments.length) {
			return null;
		}
		for (var i = 0; i + prefixSegments.length <= pathSegments.length; i++) {
			var matches = true;
			for (var j = 0; j < prefixSegments.length; j++) {
				if (pathSegments[i + j] !== prefixSegments[j]) {
					matches = false;
					break;
				}
			}
			if (matches) {
				var routeSegments = pathSegments.slice(i + prefixSegments.length);
				return routeSegments.length ? '/' + routeSegments.join('/') : null;
			}
		}
		return null;
	},
	/**
	 * Client-side twin of RestRoute::segments_match() — same two wildcard forms: `*` as
	 * any segment except the last matches exactly one segment, `*` as the LAST segment
	 * matches the fixed prefix before it plus any number of further segments.
	 *
	 * @param {string[]} routeSegments
	 * @param {string[]} patternSegments
	 * @returns {boolean}
	 */
	routeSegmentsMatch : function(routeSegments, patternSegments) {
		if (!patternSegments.length) {
			return false;
		}
		var lastIndex = patternSegments.length - 1;
		var isSuffix = patternSegments[lastIndex] === '*';
		var fixed = isSuffix ? patternSegments.slice(0, lastIndex) : patternSegments;
		if (isSuffix) {
			if (routeSegments.length < fixed.length) {
				return false;
			}
		} else if (routeSegments.length !== fixed.length) {
			return false;
		}
		for (var i = 0; i < fixed.length; i++) {
			if (fixed[i] === '*') {
				continue;
			}
			if (fixed[i].toLowerCase() !== String(routeSegments[i]).toLowerCase()) {
				return false;
			}
		}
		return true;
	},
	/**
	 * Whether `route` is covered by any line of `routes` (POW_REST_ROUTES, one per line —
	 * same list get_patterns() returns for patterns/actions). Used by checkPatterns() so a
	 * captured entry whose request targeted an already-monitored route shows "Covered"
	 * instead of a false "Not covered".
	 *
	 * @param {string|null|undefined} route
	 * @param {string[]|null|undefined} routes
	 * @returns {boolean}
	 */
	routeCovered : function(route, routes) {
		if (!route || !Array.isArray(routes) || !routes.length) {
			return false;
		}
		var routeSegments = String(route).split('/').filter(Boolean);
		if (!routeSegments.length) {
			return false;
		}
		return routes.some(function(line) {
			var patternSegments = String(line).split('/').filter(Boolean);
			return gdpr_compliant_recaptcha_analysis.routeSegmentsMatch(routeSegments, patternSegments);
		});
	},
	/** Name heuristic for password-carrying fields (fallback when no type info exists). */
	isPasswordKey : function(key) {
		const k = String(key).toLowerCase();
		return k.includes('password') || k.includes('passwort') || /^(pwd|passwd|pass|pass1|pass2|user_pass)$/.test(k);
	},
	/** Remove password field VALUES from a captured submission before it is persisted.
	 * Security-relevant: analysis entries are stored server-side and readable by every
	 * admin — without this, one admin logging in (or a user submitting a password form)
	 * while direct-analysis mode is active would leak the cleartext password to all
	 * other admins. Three layers, most authoritative first:
	 *  1. The plugin's own hashPWFields marker (recaptcha-gdpr-pow.js injects it into
	 *     every form at init, listing the form's input[type=password] names) — it
	 *     travels inside the serialized body, so it also covers the XHR/fetch paths.
	 *  2. A live DOM check on the form (form-capture path only).
	 *  3. A key-name heuristic — covers dynamically added forms (which never got the
	 *     marker) and hand-built ajax bodies. A false positive only costs one field in
	 *     an analysis capture; a false negative would leak a password.
	 * Must run BEFORE stripPluginFields(), which deletes the hashPWFields marker.
	 */
	stripPasswordFields : function(jsonData, form) {
		if (!jsonData || typeof jsonData !== 'object') {
			return jsonData;
		}
		if (typeof jsonData['hashPWFields'] === 'string') {
			try {
				JSON.parse(atob(jsonData['hashPWFields'])).forEach(nested => {
					const segments = [];
					let node = nested;
					while (node && typeof node === 'object') {
						const key = Object.keys(node)[0];
						if (key === undefined) {
							break;
						}
						segments.push(key);
						node = node[key];
					}
					gdpr_compliant_recaptcha_analysis.removeByPath(jsonData, segments);
				});
			} catch (e) {
				// Malformed marker — layers 2/3 below still apply.
			}
		}
		if (form && form.querySelectorAll) {
			form.querySelectorAll('input[type="password"][name]').forEach(input => {
				gdpr_compliant_recaptcha_analysis.removeByPath(jsonData, input.getAttribute('name').match(/[^\[\]]+/g) || []);
			});
		}
		(function walk(obj) {
			if (!obj || typeof obj !== 'object') {
				return;
			}
			Object.keys(obj).forEach(key => {
				if (gdpr_compliant_recaptcha_analysis.isPasswordKey(key)) {
					delete obj[key];
				} else {
					walk(obj[key]);
				}
			});
		})(jsonData);
		return jsonData;
	},
};

// Expose the pure, DOM-independent helpers for the Node-based regression tests
// (tests/js/, run via `node --test`) — same pattern as recaptcha-gdpr-pow.js's export
// block. No effect in the browser: `module` is undefined there, so this is skipped and
// the file stays a plain enqueued script.
if ( typeof module !== 'undefined' && module.exports ) {
	module.exports = {
		extractRestRoute : gdpr_compliant_recaptcha_analysis.extractRestRoute,
		routeSegmentsMatch : gdpr_compliant_recaptcha_analysis.routeSegmentsMatch,
		routeCovered : gdpr_compliant_recaptcha_analysis.routeCovered,
	};
}
