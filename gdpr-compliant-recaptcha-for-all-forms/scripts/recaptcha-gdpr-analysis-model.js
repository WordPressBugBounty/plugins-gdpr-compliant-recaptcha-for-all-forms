/**
 * Direct-analysis overlay: the captured-entry model.
 *
 * Part of the direct-analysis overlay, split out of recaptcha-gdpr-analysis.js
 * (Dateigroessen-Welle 3, PLAN-DATEIGROESSE.md — the file was 1625 lines). Pure move,
 * no behaviour change: the functions below are byte-identical to their former places in
 * the object literal, they are only attached to it from here.
 *
 * What lives here: everything that turns an intercepted request into an entry of
 * gdpr_compliant_recaptcha_analysis.jsonArray and keeps that array in shape — the
 * structural JSON comparison (recursiveComparison/findMissingElements/
 * compareJSONObjects), the name heuristic (seekName), the create-or-update step
 * (updateJSONObject), the coverage derivation against the loaded patterns/actions/
 * routes (checkPatterns), and the nested-key helpers the form/ajax bodies are parsed
 * with (convertStringToJsonObject/deepMerge/mergeNestedArrays/formToJSON/
 * insertIntoNestedObject).
 *
 * What deliberately does NOT live here: anything that talks to the network (capture
 * module) or touches the DOM (ui/guide modules). checkPatterns() reads the patterns/
 * actions/routes arrays but never fetches them.
 *
 * Loaded by Analysis::add_javascript() with a wp_enqueue_script() dependency that
 * guarantees recaptcha-gdpr-analysis.js (which DECLARES the object) ran first — see the
 * chain documented in that file's header.
 */

Object.assign( gdpr_compliant_recaptcha_analysis, {
	findMissingElements : function(obj1, obj2) {
		const diff = {};
		for (const key in obj2) {
			if (obj2.hasOwnProperty(key)) {
				if (!obj1.hasOwnProperty(key)) {
					diff[key] = obj2[key];
				} else if (typeof obj2[key] === 'object' && obj2[key] !== null) {
					const nestedDiff = gdpr_compliant_recaptcha_analysis.findMissingElements(obj1[key], obj2[key]);
					if (Object.keys(nestedDiff).length > 0) {
						diff[key] = nestedDiff;
					}
				}
			}
		}
		return diff;
	},
	recursiveComparison: function(obj1, obj2, ignoreNull) {
		for (const key in obj1) {
			if (obj1.hasOwnProperty(key)) {
				if (!obj2.hasOwnProperty(key)) {
					return false;
				}
				if (typeof obj1[key] === 'object' && obj1[key] !== null) {
					if (!gdpr_compliant_recaptcha_analysis.recursiveComparison(obj1[key], obj2[key])) {
						return false;
					}
				} else {
					if(!(ignoreNull && (obj1[key] === null || obj1[key] === undefined))){
						if (obj1[key] !== obj2[key]) {
							return false;
						}
					}
				}
			}
		}
		return true;
	},
	//Checks whether a JSON object 1 is comletely inherited in an JSON object 2 and if so, in addition results a JSON that contains the diff
	compareJSONObjects : function(obj1, obj2, ignoreNull = false) {
		const areEqual = gdpr_compliant_recaptcha_analysis.recursiveComparison(obj1, obj2, ignoreNull);
		let missingElements = {};
		if( areEqual )
			missingElements = gdpr_compliant_recaptcha_analysis.findMissingElements(obj1, obj2);

		return { result: areEqual, json: obj1, diff: missingElements };
	},
	/**Retrieves a probable useful name for a given JSON the represents the payload of an ajax-call in WordPress */
	seekName : function(jsonObject){
		if( 'action' in jsonObject)
			return jsonObject['action'];
		else
			return Object.keys(jsonObject)[0];
	},
	//Updating the array of JSON objects
	// route (REST_ROUTES_PLAN.md AP5): the REST route this capture's request targeted,
	// as derived by extractRestRoute() from the intercepted URL, or null for a request
	// that is not (recognisably) a REST call. Stored on the entry like ajax/wp_ajax, and
	// consulted by checkPatterns() for coverage against POW_REST_ROUTES.
	updateJSONObject : function (newJsonObject, submission = false, ajax = false, assign = false, route = null) {
		let name = gdpr_compliant_recaptcha_analysis.seekName(newJsonObject);
		let found = false;
		let wp_ajax = ajax && newJsonObject.hasOwnProperty('action') ? true : false;
		// Tracks the entry that was created/updated by this call, so callers (the submit
		// and ajax-capture paths) can hand it to persistEntry(). Stays null for the
		// assign=true restore path — those entries are already persisted server-side and
		// must not be written back.
		let resultEntry = null;
		//Check whether the field already exists. If so update the field
		for (const key in gdpr_compliant_recaptcha_analysis.jsonArray) {
			let result = null;
			let post = false;
			let diff = null;
			if( gdpr_compliant_recaptcha_analysis.jsonArray[key]['name'] == name
				|| gdpr_compliant_recaptcha_analysis.recursiveComparison(newJsonObject, gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'])
				|| gdpr_compliant_recaptcha_analysis.recursiveComparison(gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'], newJsonObject)
			){
				found = true;
				if(gdpr_compliant_recaptcha_analysis.jsonArray[key]['name'] !== name && ajax){
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['name'] = name;
				}
				// Only overwrite when THIS call actually saw a route — a later capture of
				// the same submission via a path that carries no URL (e.g. a plain form
				// re-submit) must not erase a route learned earlier.
				if(route){
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['route'] = route;
				}
				//Check whether either the existing field, or the new field is a post and update it respectively
				if(!ajax && gdpr_compliant_recaptcha_analysis.jsonArray[key]['ajax']){
					diff = gdpr_compliant_recaptcha_analysis.findMissingElements(newJsonObject, gdpr_compliant_recaptcha_analysis.jsonArray[key]['json']);
					post = true;
				}else if(ajax && !gdpr_compliant_recaptcha_analysis.jsonArray[key]['ajax']){
					diff = gdpr_compliant_recaptcha_analysis.findMissingElements(gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'], newJsonObject);
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'] = newJsonObject;
					post = true;
				}
				//Update other fields if posts was found either way round, otherwise update all fields
				if(post){
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['diff'] = diff;
					if(submission)
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['submission'] = submission;
					if(ajax)
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['ajax'] = ajax;
					if(wp_ajax)
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['wp_ajax'] = wp_ajax;
				}else{
					diff = gdpr_compliant_recaptcha_analysis.findMissingElements(gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'], newJsonObject);
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['diff'] = diff;
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'] = newJsonObject;
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['submission'] = submission;
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['ajax'] = ajax;
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['wp_ajax'] = wp_ajax;
				}

				gdpr_compliant_recaptcha_analysis.createAkkordeonElements (key, true);
				resultEntry = gdpr_compliant_recaptcha_analysis.jsonArray[key];
				break;
			}
		}
		if(!found){
			if(assign){
				gdpr_compliant_recaptcha_analysis.jsonArray = newJsonObject;
				var keys = Object.keys(gdpr_compliant_recaptcha_analysis.jsonArray);
				// Loop through the keys using forEach
				keys.forEach(function(key) {
					gdpr_compliant_recaptcha_analysis.createAkkordeonElements (key);
				});
			}else{
				gdpr_compliant_recaptcha_analysis.jsonArray.push({
						json: newJsonObject, // jsonData object
						diff: {}, // Additional meta information
						checked: false,
						found: false,
						saved: false,
						submission: submission,
						ajax : ajax,
						wp_ajax: wp_ajax,
						name: name,
						route: route,
				});
				var keys = Object.keys(gdpr_compliant_recaptcha_analysis.jsonArray);
				var lastKey = keys[keys.length - 1];
				gdpr_compliant_recaptcha_analysis.createAkkordeonElements (lastKey);
				resultEntry = gdpr_compliant_recaptcha_analysis.jsonArray[lastKey];
			}
		}
		return resultEntry;
	},
	/** Derives coverage (jsonArray[key].found) fresh against the currently loaded
	 * patterns/actions on every call — NOT a one-shot "check once, cache forever": a
	 * pattern/action removed in the background (e.g. by the admin editing scope in another
	 * tab) must make a previously-covered entry show as uncovered again on the next call,
	 * which a stale cached found=true would hide. Called both from createAkkordeonElements()
	 * (render-time) and refreshCoverageAndGuide() (after each capture, following a fresh
	 * getPatterns() fetch). The `checked` field on entries is no longer consulted here (kept
	 * on the objects, but unused) — every entry is always re-derived.
	 */
	checkPatterns : function(){
		for (const key in gdpr_compliant_recaptcha_analysis.jsonArray) {
			if (gdpr_compliant_recaptcha_analysis.jsonArray.hasOwnProperty(key)) {
				const currentJson = gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'];
				gdpr_compliant_recaptcha_analysis.jsonArray[key]['found'] = false;
				// Compare the 'json' attribute of currentJson with each comparisonJson
				for (const patternKey in gdpr_compliant_recaptcha_analysis.patterns) {
					const currentPattern = gdpr_compliant_recaptcha_analysis.patterns[patternKey];
					if (gdpr_compliant_recaptcha_analysis.compareJSONObjects(currentPattern, currentJson, true)['result']) {
						// Do something if they are equal
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['found'] = true;
						break; // Exit the loop once a match is found
					}
				}
				// Compare the "ation"-attribute inside the 'json' attribute of currentJson with each comparisonJson
				if (
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['json']['action']
					&& gdpr_compliant_recaptcha_analysis.actions
					&& gdpr_compliant_recaptcha_analysis.actions.length
					&& gdpr_compliant_recaptcha_analysis.actions.includes(gdpr_compliant_recaptcha_analysis.jsonArray[key]['json']['action'])
				){
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['found'] = true;
				}
				// Third signature class (REST_ROUTES_PLAN.md AP5): the entry's captured
				// REST route (if any) against POW_REST_ROUTES — so a form builder that
				// submits over REST and is already monitored by route shows "Covered"
				// instead of the field-pattern/action checks above (which never see a
				// route) reporting a false "Not covered".
				if (
					gdpr_compliant_recaptcha_analysis.routeCovered(
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['route'],
						gdpr_compliant_recaptcha_analysis.routes
					)
				) {
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['found'] = true;
				}
			}
		}
	},
	insertIntoNestedObject: function (existingObject, inputString, value) {
		// String in ein Array aufteilen
		var keys = inputString.split("->");
		
		// Aktuelles Objekt auf das bestehende Objekt setzen
		var currentObject = existingObject;

		// Iteriere durch die Schlüssel und erstelle das verschachtelte assoziative Array
		for (var i = 0; i < keys.length; i++) {
			var key = keys[i];
			if (i === keys.length - 1) {
				// Wenn wir den letzten Schlüssel erreicht haben, setze den Wert
				currentObject[key] = value;
			} else {
				// Andernfalls erstelle ein neues leeres Objekt, wenn der Schlüssel noch nicht existiert
				if (!currentObject[key]) {
					currentObject[key] = {};
				}
				currentObject = currentObject[key];
			}
		}
	},
	// Function to convert a nested name of an HTML element into a JSON object
	convertStringToJsonObject : function(inputString, value) {
		var keys = inputString.split(/\]\[|\[|\]/).filter(function(key) {
			return key.length > 0;
		});
		var result = {};

		keys.reduce(function(obj, key, index, array) {
			obj[key] = index === array.length - 1 ? value : {};
			return obj[key];
		}, result);

		return result;
	},
	// Merging nested objects
	deepMerge : function(target, source) {
		for (const key in source) {
			if (source.hasOwnProperty(key)) {
				if (typeof source[key] === 'object' && source[key] !== null) {
					if (!target[key]) {
						target[key] = Array.isArray(source[key]) ? [] : {};
					}
					gdpr_compliant_recaptcha_analysis.deepMerge(target[key], source[key]);
				} else {
					target[key] = source[key];
				}
			}
		}
		return target;
	},
	// Merging nested and flat objects
	mergeNestedArrays : function(arr1, arr2) {
		let mergedArray;

		if (Array.isArray(arr1)) {
			mergedArray = [...arr1, ...arr2];
		} else if (typeof arr1 === 'object' && arr1 !== null) {
			mergedArray = Array.isArray(arr2) ? [...arr2] : [arr2];
			for (const key in arr1) {
				if (arr1.hasOwnProperty(key)) {
					if( typeof arr1[key] !== 'object' ){
						mergedArray.push({ [key]: arr1[key] });
					}else{
						mergedArray.push({ [key]: gdpr_compliant_recaptcha_analysis.deepMerge({}, arr1[key]) });
					}
				}
			}
		} else {
			mergedArray = Array.isArray(arr2) ? [...arr2] : [arr2];
		}
		return mergedArray.reduce((merged, obj) => {
			gdpr_compliant_recaptcha_analysis.deepMerge(merged, obj);
			return merged;
		}, {});
	},
	//Converts form data to a JSON
	formToJSON : function(data){
		var jsonData;
		if (data instanceof FormData) {
			// If data is a FormData object, convert it to JSON
			jsonData = {};
			data.forEach(function(value, key) {
				if(key.includes('[')){
					jsonData = gdpr_compliant_recaptcha_analysis.mergeNestedArrays(jsonData, gdpr_compliant_recaptcha_analysis.convertStringToJsonObject(key, value));
				}else{
					jsonData[key] = value;
				}
			});
		} else if (typeof data === 'string') {
			// If data is a string, try to parse it as JSON
			try {
				jsonData = JSON.parse(data);
			} catch (error) {
				// If parsing fails, treat it as URL-encoded string
				jsonData = {};
				data.split('&').forEach(function(pair) {
					pair = pair.split('=');
					jsonData[pair[0]] = decodeURIComponent(pair[1] || '');
				});
			}
		} else if (typeof data === 'object') {
			// If data is already an object, keep it as is
			jsonData = data;
		}
		return jsonData;
	},
} );
