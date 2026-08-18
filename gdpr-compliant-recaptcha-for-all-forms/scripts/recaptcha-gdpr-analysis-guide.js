/**
 * Direct-analysis overlay: the guide strip (#gdpr-guide-bar) state machine.
 *
 * Part of the direct-analysis overlay, split out of recaptcha-gdpr-analysis.js
 * (Dateigroessen-Welle 3, PLAN-DATEIGROESSE.md — the file was 1625 lines). Pure move,
 * no behaviour change: the functions below are byte-identical to their former places in
 * the object literal, they are only attached to it from here.
 *
 * What lives here: the four-state machine (armed|captured|saved|error) that replaced
 * the old stacking showInfo()/showSuccess()/showAlert() popups — its state fields, the
 * transition entry point (setGuideState), the renderer (renderGuide) and the
 * "Review entry" jump (reviewEntry).
 *
 * Separate from the ui module because it is a state machine, not a renderer of captured
 * data: it is driven by the capture paths (refreshCoverageAndGuide) and by
 * createAkkordeonElements, and it owns exactly one DOM element, which
 * ensureAnalysisWindow() creates for it.
 *
 * Loaded by Analysis::add_javascript() with a wp_enqueue_script() dependency that
 * guarantees recaptcha-gdpr-analysis.js (which DECLARES the object) ran first — see the
 * chain documented in that file's header.
 */

Object.assign( gdpr_compliant_recaptcha_analysis, {
	/** Guide strip state machine (#gdpr-guide-bar), replacing the old stacking
	 * showInfo()/showSuccess()/showAlert() popups. Lives INSIDE the analysis window (sticky
	 * strip directly below the header - see ensureAnalysisWindow()), not as a standalone
	 * viewport-corner element. One element, replaced (not stacked) on every state change.
	 */
	guideState : 'armed',
	guideCtx : {},
	// Tracks the akkordeonId the guide last showed 'captured' for, so
	// refreshCoverageAndGuide() only auto-reverts to 'armed' when the entry that JUST became
	// covered is the one the guide is currently pointing at (not some unrelated entry).
	lastCapturedAkkordeonId : null,
	guideSavedTimer : null,

	/** Set the guide bar to a new state (armed|captured|saved|error) with optional context:
	 *  - captured: { name, akkordeonId } — akkordeonId enables the "Review entry" button.
	 *  - saved:    { type: 'pattern'|'action' }
	 *  - error:    { message }
	 * Auto-reverts to 'armed' ~4s after 'saved'.
	 */
	setGuideState : function(state, ctx) {
		gdpr_compliant_recaptcha_analysis.guideState = state;
		gdpr_compliant_recaptcha_analysis.guideCtx = ctx || {};
		if (state === 'captured') {
			gdpr_compliant_recaptcha_analysis.lastCapturedAkkordeonId =
				(ctx && ctx.akkordeonId !== undefined) ? ctx.akkordeonId : null;
		}
		if (gdpr_compliant_recaptcha_analysis.guideSavedTimer) {
			clearTimeout(gdpr_compliant_recaptcha_analysis.guideSavedTimer);
			gdpr_compliant_recaptcha_analysis.guideSavedTimer = null;
		}
		if (state === 'saved') {
			gdpr_compliant_recaptcha_analysis.guideSavedTimer = setTimeout(function() {
				gdpr_compliant_recaptcha_analysis.setGuideState('armed');
			}, 4000);
		}
		gdpr_compliant_recaptcha_analysis.renderGuide();
	},

	/** (Re)render the guide strip from the current guideState/guideCtx into #gdpr-guide-bar.
	 * The strip element itself lives inside the analysis window (ensureAnalysisWindow()); if
	 * the window hasn't been created yet (e.g. setGuideState() called very early), this
	 * creates it first so there's always somewhere to render into.
	 */
	renderGuide : function() {
		var state = gdpr_compliant_recaptcha_analysis.guideState;
		var ctx = gdpr_compliant_recaptcha_analysis.guideCtx;
		var bar = document.getElementById('gdpr-guide-bar');
		if (!bar) {
			gdpr_compliant_recaptcha_analysis.ensureAnalysisWindow();
			bar = document.getElementById('gdpr-guide-bar');
		}
		bar.className = 'gdpr-guide-state-' + state;
		bar.innerHTML = '';

		var panel = document.createElement('div');
		panel.className = 'gdpr-guide-panel';

		var icon = document.createElement('div');
		icon.className = 'gdpr-guide-icon';
		if (state === 'armed') {
			icon.classList.add('gdpr-guide-pulse-dot');
		} else if (state === 'saved') {
			icon.textContent = '✓';
		} else if (state === 'error') {
			icon.textContent = '✖';
		} else if (state === 'captured') {
			icon.textContent = '❗';
		}

		var textWrap = document.createElement('div');
		textWrap.className = 'gdpr-guide-text';

		var title = document.createElement('div');
		title.className = 'gdpr-guide-title';
		var subtitle = document.createElement('div');
		subtitle.className = 'gdpr-guide-subtitle';

		var actionBtn = null;

		if (state === 'armed') {
			title.textContent = gdprAnalysis.i18n.guideArmedTitle;
			// After a server-side restore of earlier captures (all of them covered),
			// explain why entries are already listed although nothing was submitted
			// on this page view — plain "submit a form" would look buggy.
			subtitle.textContent = ctx.restoredCount
				? gdprAnalysis.i18n.guideRestoredSubtitle.replace('%d', ctx.restoredCount)
				: gdprAnalysis.i18n.guideArmedSubtitle;
		} else if (state === 'captured') {
			title.textContent = gdprAnalysis.i18n.guideCapturedTitle.replace('%s', ctx.name || '');
			subtitle.textContent = gdprAnalysis.i18n.guideCapturedSubtitle;
			if (ctx.akkordeonId !== undefined && ctx.akkordeonId !== null) {
				actionBtn = document.createElement('button');
				actionBtn.type = 'button';
				actionBtn.className = 'gdpr-guide-action';
				actionBtn.textContent = gdprAnalysis.i18n.guideReviewEntry;
				actionBtn.addEventListener('click', function() {
					gdpr_compliant_recaptcha_analysis.reviewEntry(ctx.akkordeonId);
				});
			}
		} else if (state === 'saved') {
			title.textContent = ctx.type === 'action' ? gdprAnalysis.i18n.guideActionSaved : gdprAnalysis.i18n.guidePatternSaved;
			subtitle.textContent = gdprAnalysis.i18n.guideSavedSubtitle;
		} else if (state === 'error') {
			title.textContent = ctx.message || '';
		}

		textWrap.appendChild(title);
		if (subtitle.textContent) {
			textWrap.appendChild(subtitle);
		}

		panel.appendChild(icon);
		panel.appendChild(textWrap);

		if (state !== 'error') {
			var dots = document.createElement('div');
			dots.className = 'gdpr-guide-dots';
			var filled = state === 'armed' ? 1 : (state === 'captured' ? 2 : 3);
			for (var i = 0; i < 3; i++) {
				var dot = document.createElement('span');
				dot.className = 'gdpr-guide-dot' + (i < filled ? ' gdpr-guide-dot-active' : '');
				dots.appendChild(dot);
			}
			panel.appendChild(dots);
		}

		if (actionBtn) {
			panel.appendChild(actionBtn);
		}

		bar.appendChild(panel);
	},

	/** "Review entry" action from the guide bar's captured state: scroll the analysis
	 * window to the given accordion entry, open it if collapsed, and briefly highlight it.
	 */
	reviewEntry : function(id) {
		var button = document.getElementById('akkordeonButton_' + id);
		if (!button) {
			return;
		}
		var unit = document.getElementById(button.getAttribute('peer'));
		if (unit && unit.style.display !== 'block') {
			button.classList.add('akkordeonButtonAktiv');
			unit.style.display = 'block';
		}
		button.scrollIntoView({ behavior: 'smooth', block: 'center' });
		button.classList.add('gdpr-highlight');
		setTimeout(function() {
			button.classList.remove('gdpr-highlight');
		}, 1500);
	},
} );
