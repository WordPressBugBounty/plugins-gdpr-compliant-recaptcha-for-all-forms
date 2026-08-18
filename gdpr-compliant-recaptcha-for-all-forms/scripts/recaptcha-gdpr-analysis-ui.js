/**
 * Direct-analysis overlay: the analysis window and its accordion.
 *
 * Part of the direct-analysis overlay, split out of recaptcha-gdpr-analysis.js
 * (Dateigroessen-Welle 3, PLAN-DATEIGROESSE.md — the file was 1625 lines). Pure move,
 * no behaviour change: the functions below are byte-identical to their former places in
 * the object literal, they are only attached to it from here.
 *
 * What lives here: everything that renders — the window shell
 * (ensureAnalysisWindow: container, sticky header, guide-strip element, body), one
 * accordion entry per captured submission (createAkkordeonElements), the per-entry
 * key/value table (createFormForNestedObject), the desktop-only drag behaviour
 * (dragElement) and the spinner/blocking-overlay helpers.
 *
 * The guide STRIP's own state machine is one module further down the chain
 * (recaptcha-gdpr-analysis-guide.js): this file creates the #gdpr-guide-bar element and
 * calls setGuideState()/renderGuide() at runtime, but owns neither.
 *
 * Loaded by Analysis::add_javascript() with a wp_enqueue_script() dependency that
 * guarantees recaptcha-gdpr-analysis.js (which DECLARES the object) ran first — see the
 * chain documented in that file's header.
 */

Object.assign( gdpr_compliant_recaptcha_analysis, {
	//This function creates a form out of a nested json array
	createFormForNestedObject : function(obj, parentKey = null, form, id, wp_ajax, diff=false) {
		if(!parentKey && !diff){
			var tableHeadings = null;

			if(!wp_ajax)
				tableHeadings = [
					gdprAnalysis.i18n.choosePattern, 
					gdprAnalysis.i18n.key,
					gdprAnalysis.i18n.choosePattern,
					gdprAnalysis.i18n.key
				];
			else
				tableHeadings = [
					gdprAnalysis.i18n.key,
					gdprAnalysis.i18n.value
				];
	
			// Erstelle die Kopfspalte der Tabelle
			const thead = document.createElement("thead");
			const headingRow = document.createElement("tr");
		
			tableHeadings.forEach(headingText => {
				const th = document.createElement("th");
				th.textContent = headingText;
				th.style.border = "1px solid #ddd";
				th.style.padding = "8px";
				th.style.textAlign = "left";
				headingRow.appendChild(th);
			});
		
			thead.appendChild(headingRow);
			form.appendChild(thead);
		}
	
		for (const key in obj) {
			if (obj.hasOwnProperty(key)) {
				const fullPath = parentKey ? `${parentKey}_${key}` : key;
				const value = obj[key];
	
				// Nur Eingabefelder für einfache Werte erstellen, nicht für verschachtelte Objekte
				if (typeof value !== "object" || value === null) {
					if(diff){
						var diff_element = document.getElementsByClassName('row-'+fullPath);
						diff_element[0].classList.add('hiddenInput');
					}else{
						// Erstelle eine Zeile in der Tabelle
						const row = document.createElement("tr");
						row.classList.add('row-'+fullPath);
						if(!wp_ajax){
							var hiddenInputs = document.querySelectorAll('input[name="'+fullPath+'"][type="hidden"], button[name="'+fullPath+'"], input[name="'+fullPath+'"][type="submit"]');
							if(hiddenInputs.length)
								row.classList.add('hiddenInput');

							// 1. Spalte: Checkbox für den Key
							const keyCheckboxCell = document.createElement("td");
							keyCheckboxCell.style.border = "1px solid #ddd";
							keyCheckboxCell.style.padding = "8px";
							const keyCheckbox = document.createElement("input");
							keyCheckbox.type = "checkbox";
							keyCheckbox.classList.add('gdpr-key-check-' + id);
							keyCheckbox.setAttribute('peer', `value_check_${fullPath}` + id);
							keyCheckbox.id = `key_check_${fullPath}` + id;
							keyCheckbox.name = `key_check_${fullPath}` + id;
							keyCheckbox.value = fullPath;
							keyCheckbox.onchange = function() {
								var valueCheckbox = document.getElementById('value_check_' + fullPath + id);
								if(valueCheckbox.checked)
									valueCheckbox.checked = this.checked;
							};
							keyCheckboxCell.appendChild(keyCheckbox);
							row.appendChild(keyCheckboxCell);
						}
		
						// 2. Spalte: Eingabefeld für den Key
						const keyInputCell = document.createElement("td");
						keyInputCell.style.border = "1px solid #ddd";
						keyInputCell.style.padding = "8px";
						const keyInput = document.createElement("input");
						keyInput.type = "text";
						keyInput.id = `key_input_${fullPath}` + id;
						keyInput.name = `key_input_${fullPath}` + id;
						keyInput.value = fullPath;
						keyInput.readOnly = true; 
						keyInputCell.appendChild(keyInput);
						row.appendChild(keyInputCell);
						
						if(!wp_ajax){
							// 3. Spalte: Checkbox für den Wert
							const valueCheckboxCell = document.createElement("td");
							valueCheckboxCell.style.border = "1px solid #ddd";
							valueCheckboxCell.style.padding = "8px";
							const valueCheckbox = document.createElement("input");
							valueCheckbox.type = "checkbox";
							valueCheckbox.classList.add('gdpr-value-check-' + id);
							valueCheckbox.setAttribute('peer', `key_check_${fullPath}` + id);
							valueCheckbox.id = `value_check_${fullPath}` + id;
							valueCheckbox.name = `value_check_${fullPath}` + id;
							valueCheckbox.value = value;
							valueCheckbox.onchange = function() {
								var keyCheckbox = document.getElementById('key_check_' + fullPath + id);
								if(!keyCheckbox.checked)
									keyCheckbox.checked = this.checked;
							};
							valueCheckboxCell.appendChild(valueCheckbox);
							row.appendChild(valueCheckboxCell);
						}
		
						// 4. Spalte: Eingabefeld für den Wert
						const valueInputCell = document.createElement("td");
						valueInputCell.style.border = "1px solid #ddd";
						valueInputCell.style.padding = "8px";
						const valueInput = document.createElement("input");
						valueInput.type = "text";
						valueInput.id = `value_input_${fullPath}` + id;
						valueInput.name = `value_input_${fullPath}` + id;
						valueInput.value = value;
						valueInput.readOnly = true; 
						valueInputCell.appendChild(valueInput);
						row.appendChild(valueInputCell);
		
						// Füge die Zeile der Tabelle hinzu
						form.appendChild(row);
					}
				}
	
				// Wenn es sich um ein verschachteltes Objekt handelt, rufe die Funktion rekursiv auf
				if (typeof value === "object" && value !== null) {
					gdpr_compliant_recaptcha_analysis.createFormForNestedObject(value, fullPath, form, id, wp_ajax, diff);
				}
			}
		}
	},

	/** Lazily create (or return the existing) analysis window shell: outer container,
	 * header, guide strip (#gdpr-guide-bar - see renderGuide()), and body. Called both from
	 * initiateAnalysis() (so the window - including the guide strip - exists immediately at
	 * init, even before any entry was captured) and from createAkkordeonElements() (so a
	 * capture racing ahead of that init call still gets a window). Idempotent: a second call
	 * is a cheap no-op beyond returning the existing body element.
	 */
	ensureAnalysisWindow : function() {
		var gdprContainerBody = document.getElementById("gdpr-analysis-containerbody");
		if (gdprContainerBody) {
			return gdprContainerBody;
		}

		// Single fixed, top-centered element (no nested fixed-in-fixed wrapper — see
		// the comment on #gdpr-analysis-container in style_analysis.css for why).
		var outerContainer = document.createElement("div");
		outerContainer.id = "gdpr-analysis-container";
		document.body.appendChild(outerContainer);
		outerContainer.offsetWidth;
		outerContainer.style.opacity = "1";

		// Header + guide strip live together in a sticky wrapper so both stay visible
		// while the accordion body scrolls underneath them (see #gdpr-analysis-sticky in
		// style_analysis.css).
		var stickyWrap = document.createElement("div");
		stickyWrap.id = "gdpr-analysis-sticky";
		outerContainer.appendChild(stickyWrap);

		var gdprContainerHeader = document.createElement("div");
		gdprContainerHeader.id = "gdpr-analysis-containerheader";
		stickyWrap.appendChild(gdprContainerHeader);

		var headerTitle = document.createElement("div");
		headerTitle.classList.add("gdpr-header-title");
		headerTitle.textContent = gdprAnalysis.i18n.windowTitle;
		gdprContainerHeader.appendChild(headerTitle);

		var headerLogo = document.createElement("div");
		headerLogo.classList.add("logoImage");
		gdprContainerHeader.appendChild(headerLogo);

		// Guide strip: directly after the header, inside the sticky wrapper - filled by
		// renderGuide() (invoked below for the initial 'armed' render).
		var guideBar = document.createElement("div");
		guideBar.id = "gdpr-guide-bar";
		stickyWrap.appendChild(guideBar);

		gdprContainerBody = document.createElement("div");
		gdprContainerBody.id = "gdpr-analysis-containerbody";
		outerContainer.appendChild(gdprContainerBody);

		// Make the window draggable via its header (desktop only — see dragElement()).
		gdpr_compliant_recaptcha_analysis.dragElement(outerContainer);

		// Render the guide strip immediately so an empty window right after init isn't
		// blank; reflects whatever guideState/guideCtx already hold (default 'armed').
		gdpr_compliant_recaptcha_analysis.renderGuide();

		return gdprContainerBody;
	},
	//This function creates the elements containing a form for each json
	createAkkordeonElements : function(id, update = false){
		gdpr_compliant_recaptcha_analysis.checkPatterns();
		var akkordeonEinheit = null;
		var found = gdpr_compliant_recaptcha_analysis.jsonArray[id]['found'];
		var submission = gdpr_compliant_recaptcha_analysis.jsonArray[id]['submission'];
		var wp_ajax = gdpr_compliant_recaptcha_analysis.jsonArray[id]['wp_ajax'];
		var name = gdpr_compliant_recaptcha_analysis.jsonArray[id]['name'];
		var ajax = gdpr_compliant_recaptcha_analysis.jsonArray[id]['ajax'];
		var route = gdpr_compliant_recaptcha_analysis.jsonArray[id]['route'];
		var diff = null;
		if(gdpr_compliant_recaptcha_analysis.jsonArray[id]['diff'])
			diff = gdpr_compliant_recaptcha_analysis.jsonArray[id]['diff'];
		var json = gdpr_compliant_recaptcha_analysis.jsonArray[id]['json'];
		if(update){
			var gdprContainerOld = document.getElementById('gdprContainer_' + id);
			if (gdprContainerOld) 
				gdprContainerOld.remove();
		}
		var gdprContainerBody = gdpr_compliant_recaptcha_analysis.ensureAnalysisWindow();
		const gdprContainer = document.createElement("div");
		gdprContainer.id = 'gdprContainer_' + id;
		gdprContainer.classList.add("gdprContainer");
		gdprContainer.style.padding = "10px";
		gdprContainer.style.width = "100%";
		gdprContainerBody.appendChild(gdprContainer);

		const akkordeonButton = document.createElement("akkordeonButton");
		akkordeonButton.classList.add("akkordeonButton");
		var statusIcon = '';
		var notCovered = false;

		if( submission && !found ){
			akkordeonButton.classList.add("hiddenInput");
			statusIcon = '❗';
			notCovered = true;
		}else if( submission && found ){
			akkordeonButton.classList.add("coveredSubmissionType");
			statusIcon = '✔️';
		}else{
			akkordeonButton.classList.add("ordinarySubmissionType");
		}
		if(notCovered && !update){
			gdpr_compliant_recaptcha_analysis.setGuideState('captured', { name: name, akkordeonId: id });
		}
		akkordeonButton.id = "akkordeonButton_" + id;
		akkordeonButton.setAttribute("peer", "akkordeonEinheit_" + id);

		// Built via createElement/textContent (not innerHTML) — `name` originates from a
		// captured form submission and must never be interpreted as HTML.
		const akkordeonRow = document.createElement("div");
		akkordeonRow.classList.add("gdpr-akkordeon-row");

		if(statusIcon){
			const statusIconEl = document.createElement("span");
			statusIconEl.classList.add("gdpr-status-icon");
			statusIconEl.textContent = statusIcon;
			akkordeonRow.appendChild(statusIconEl);
		}

		const nameEl = document.createElement("strong");
		nameEl.classList.add("gdpr-entry-name");
		nameEl.textContent = name;
		nameEl.title = name;
		akkordeonRow.appendChild(nameEl);

		const badgesEl = document.createElement("span");
		badgesEl.classList.add("gdpr-badges");
		if(submission){
			const coverBadge = document.createElement("span");
			coverBadge.classList.add("gdpr-badge", found ? "gdpr-badge-covered" : "gdpr-badge-not-covered");
			coverBadge.textContent = found ? gdprAnalysis.i18n.covered : gdprAnalysis.i18n.notCovered;
			badgesEl.appendChild(coverBadge);
		}
		if(ajax){
			const ajaxBadge = document.createElement("span");
			ajaxBadge.classList.add("gdpr-badge", "gdpr-badge-neutral");
			ajaxBadge.textContent = gdprAnalysis.i18n.ajax;
			badgesEl.appendChild(ajaxBadge);
		}
		if(submission){
			const submissionBadge = document.createElement("span");
			submissionBadge.classList.add("gdpr-badge", "gdpr-badge-neutral");
			submissionBadge.textContent = gdprAnalysis.i18n.submission;
			badgesEl.appendChild(submissionBadge);
		}
		// REST route this capture's request targeted (REST_ROUTES_PLAN.md AP5), when the
		// interceptor recognised one (extractRestRoute()). Shown, not clickable — unlike
		// Message_Page::render_message()'s "Monitor this route" button, this overlay has
		// no server round-trip for a one-click add; the admin adds it via Save pattern/
		// action like any other captured entry, or through the message detail view once
		// the request is also persisted as a message (POW_ANALYSIS_MODE).
		if(route){
			const routeBadge = document.createElement("span");
			routeBadge.classList.add("gdpr-badge", "gdpr-badge-neutral");
			routeBadge.textContent = (gdprAnalysis.i18n.restRouteLabel || '') + ' ' + route;
			routeBadge.title = route;
			badgesEl.appendChild(routeBadge);
		}
		akkordeonRow.appendChild(badgesEl);

		akkordeonButton.appendChild(akkordeonRow);
		akkordeonButton.style.opacity = "0";
		akkordeonButton.style.transition = "opacity 1s ease-in-out";
		gdprContainer.appendChild(akkordeonButton);
		akkordeonButton.offsetWidth;
		akkordeonButton.style.opacity = "1";
		
		akkordeonEinheit = document.createElement("div");
		akkordeonEinheit.classList.add("akkordeonEinheit");
		akkordeonEinheit.id = "akkordeonEinheit_" + id;
		akkordeonEinheit.style.display = "none";
		gdprContainer.appendChild(akkordeonEinheit);
		
		var akkordeon = document.getElementById("akkordeonButton_" + id);
		akkordeon.addEventListener("click", function() {
			this.classList.toggle("akkordeonButtonAktiv");
			var akkordeonEinheit = document.getElementById(this.getAttribute("peer"));
			akkordeonEinheit.style.display = akkordeonEinheit.style.display === "block" ? "none" : "block";
		});

		// Micro-hint for not-yet-covered entries, replacing the old recommendAction/
		// recommendPattern popup text — shown inline above the form on every render (not
		// just on first capture, unlike the guide bar's one-shot 'captured' toast).
		if(notCovered){
			const akkordeonHint = document.createElement("div");
			akkordeonHint.classList.add("gdpr-akkordeon-hint");
			akkordeonHint.textContent = wp_ajax ? gdprAnalysis.i18n.guideHintAction : gdprAnalysis.i18n.guideHintPattern;
			akkordeonEinheit.appendChild(akkordeonHint);
		}

		// Dynamisches Erzeugen des Formulars im Div-Element
		const gdprForm = document.createElement("form");
		gdprForm.id = "gdpr-analysis-form-" + id;
		akkordeonEinheit.appendChild(gdprForm);
		
		var buttonBefore = document.createElement('button');
		buttonBefore.classList.add('gdprSaveButton');
		if(wp_ajax){
			buttonBefore.textContent = gdprAnalysis.i18n.saveAction;
			buttonBefore.onclick = function () {
				gdpr_compliant_recaptcha_analysis.savePatterns(id);
			};
		}else{
			buttonBefore.textContent = gdprAnalysis.i18n.savePattern;
			buttonBefore.onclick = function () {
				gdpr_compliant_recaptcha_analysis.savePatterns(id);
			};
		}
		gdprForm.appendChild(buttonBefore);

		if(!wp_ajax){
			const hintColoredFields = document.createElement("div");
			hintColoredFields.classList.add("hiddenInput");
			hintColoredFields.innerHTML = gdprAnalysis.i18n.techFields;
			gdprForm.appendChild(hintColoredFields);
		}

		// Dynamisches Erzeugen der Tabelle im Formular
		const gdprTable = document.createElement("table");
		gdprTable.id = "gdpr-analysis-table-" + id;
		gdprTable.style.width = "100%";
		gdprTable.style.borderCollapse = "collapse";
		gdprTable.style.marginTop = "10px";
		gdprForm.appendChild(gdprTable);

		var buttonAfter = document.createElement('button');
		buttonAfter.classList.add('gdprSaveButton');
		if(wp_ajax){
			buttonAfter.textContent = gdprAnalysis.i18n.saveAction;
			buttonAfter.onclick = function () {
				gdpr_compliant_recaptcha_analysis.savePatterns(id);
			};
		}else{
			buttonAfter.textContent = gdprAnalysis.i18n.savePattern;
			buttonAfter.onclick = function () {
				gdpr_compliant_recaptcha_analysis.savePatterns(id);
			};
		}
		gdprForm.appendChild(buttonAfter);

		gdprForm.addEventListener('submit', function(event) {
			event.preventDefault();
		});

		gdpr_compliant_recaptcha_analysis.createFormForNestedObject(json, null, gdprTable, id, wp_ajax);
		// Funktion aufrufen, um das Formular zu erstellen
		if(diff && !wp_ajax){
			gdpr_compliant_recaptcha_analysis.createFormForNestedObject(diff, null, gdprTable, id, wp_ajax, true);
		}
		// Dragging is wired once, at window-creation time, in ensureAnalysisWindow() - the
		// window element itself isn't recreated on every accordion render.
	},
	dragElement : function(elmnt){
		// Disabled on small screens: no free-floating drag on mobile (matches the CSS
		// resize:none media query for #gdpr-analysis-container).
		if (window.matchMedia && window.matchMedia('(max-width: 640px)').matches) {
			return;
		}
		var pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
		if (document.getElementById(elmnt.id + "header")) {
		/* if present, the header is where you move the DIV from:*/
		document.getElementById(elmnt.id + "header").onmousedown = dragMouseDown;
		} else {
		/* otherwise, move the DIV from anywhere inside the DIV:*/
		elmnt.onmousedown = dragMouseDown;
		}
	
		function dragMouseDown(e) {
		e = e || window.event;
		e.preventDefault();
		// The element is initially centered via CSS (left:50% + transform:translateX(-50%),
		// see #gdpr-analysis-container). Freeze its current on-screen position as explicit
		// px left/top and drop the transform *before* the first drag delta is applied —
		// otherwise offsetLeft (unaffected by transform) wouldn't match the visual position
		// and the box would jump sideways by half its width the moment dragging starts.
		var rect = elmnt.getBoundingClientRect();
		elmnt.style.transform = 'none';
		elmnt.style.left = rect.left + 'px';
		elmnt.style.top = rect.top + 'px';
		// get the mouse cursor position at startup:
		pos3 = e.clientX;
		pos4 = e.clientY;
		document.onmouseup = closeDragElement;
		// call a function whenever the cursor moves:
		document.onmousemove = elementDrag;
		}
	
		function elementDrag(e) {
		e = e || window.event;
		e.preventDefault();
		// calculate the new cursor position:
		pos1 = pos3 - e.clientX;
		pos2 = pos4 - e.clientY;
		pos3 = e.clientX;
		pos4 = e.clientY;
		// set the element's new position:
		elmnt.style.top = (elmnt.offsetTop - pos2) + "px";
		elmnt.style.left = (elmnt.offsetLeft - pos1) + "px";
		}
	
		function closeDragElement() {
		/* stop moving when mouse button is released:*/
		document.onmouseup = null;
		document.onmousemove = null;
		}      
	},

	showSpinner : function(message=gdprAnalysis.i18n.loading) {
		var spinner = document.querySelector('.centered-spinner');
		var strongElement = document.querySelector('.centered-spinner center strong');
		strongElement.textContent = message;
		spinner.removeAttribute('hidden'); // Remove the hidden attribute
	},

	hideSpinner : function() {
		var spinner = document.querySelector('.centered-spinner');
		spinner.setAttribute('hidden', true);
	},

	hideBlockingOverlay : function(){
		var blockingOverlay = document.getElementById('blockingOverlay');
		blockingOverlay.setAttribute('hidden', true);
	},
} );
