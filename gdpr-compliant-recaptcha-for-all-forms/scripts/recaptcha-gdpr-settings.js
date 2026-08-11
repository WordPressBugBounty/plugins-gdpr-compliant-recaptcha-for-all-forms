/**
 * GDPR-Compliant ReCaptcha — settings page behaviour.
 * Counterpart: Settings_Menu::options_page() (plugin/includes/class-settings-menu.php),
 * which renders the full markup server-side (status strip, pill tabs, tab panels, option
 * rows with a help popover). This script only wires up two purely client-side interactions
 * on top of that markup — no DOM restructuring, no drag/burger-menu leftovers:
 *
 *   1. Tab switching: toggle the `hidden` attribute on .gdpr-tab-panel sections and the
 *      `is-active` class on .gdpr-pill-tab buttons, and keep the hidden
 *      #gdpr-settings-selection input in sync so the active tab survives a form submit
 *      (read server-side in options_page()).
 *   2. Help popovers: toggle the `hidden` attribute + `aria-expanded` on the matching
 *      .gdpr-help-popover, closing others on open, on outside click, and on Escape.
 */
(function () {
	'use strict';

	document.addEventListener('DOMContentLoaded', function () {
		// The pill nav sits OUTSIDE the form (sibling before it), so scope to the
		// page wrap, not the form.
		var wrap = document.querySelector('.gdpr-settings-wrap');
		if (!wrap) {
			return;
		}

		initTabs(wrap);
		initHelpPopovers(wrap);
	});

	/**
	 * Tab switching. The server renders the initially active tab (panel not hidden, pill
	 * with .is-active) — no click is triggered on load.
	 */
	function initTabs(wrap) {
		var tabs = wrap.querySelectorAll('.gdpr-pill-tab');
		var selectionInput = document.getElementById('gdpr-settings-selection');
		if (!tabs.length) {
			return;
		}

		tabs.forEach(function (tab) {
			tab.addEventListener('click', function () {
				var target = tab.getAttribute('data-tab-target');
				if (!target) {
					return;
				}

				var panel = document.getElementById(target);
				if (!panel) {
					return;
				}

				wrap.querySelectorAll('.gdpr-tab-panel').forEach(function (section) {
					section.hidden = true;
				});
				panel.hidden = false;

				tabs.forEach(function (otherTab) {
					otherTab.classList.remove('is-active');
				});
				tab.classList.add('is-active');

				if (selectionInput) {
					selectionInput.value = target;
				}

				// "Save Changes" belongs to the option panels. On Diagnostics there is
				// nothing to save — and the sticky button would sit on top of the action
				// buttons, which is both ugly and an invitation to click the wrong thing.
				toggleSubmit(target);
			});
		});

		function toggleSubmit(target) {
			var submit = document.getElementById('submit-container');
			if (submit) {
				submit.hidden = ('gdpr-tab-diagnostics' === target);
			}
		}

		// Also on load: the tab can be pre-selected from a save or a deep link.
		toggleSubmit(selectionInput ? selectionInput.value : '');
	}

	/**
	 * Help popovers, anchored to their .gdpr-help-toggle button via aria-controls.
	 */
	function initHelpPopovers(wrap) {
		var toggles = wrap.querySelectorAll('.gdpr-help-toggle');
		if (!toggles.length) {
			return;
		}

		function closeAll(except) {
			toggles.forEach(function (toggle) {
				if (toggle === except) {
					return;
				}
				var popover = document.getElementById(toggle.getAttribute('aria-controls'));
				if (popover) {
					popover.hidden = true;
				}
				toggle.setAttribute('aria-expanded', 'false');
			});
		}

		toggles.forEach(function (toggle) {
			var popover = document.getElementById(toggle.getAttribute('aria-controls'));
			if (!popover) {
				return;
			}

			toggle.addEventListener('click', function (event) {
				event.stopPropagation();
				var isOpen = toggle.getAttribute('aria-expanded') === 'true';

				closeAll(toggle);

				popover.hidden = isOpen;
				toggle.setAttribute('aria-expanded', isOpen ? 'false' : 'true');
			});
		});

		document.addEventListener('click', function (event) {
			if (event.target.closest('.gdpr-option-control')) {
				return;
			}
			closeAll();
		});

		document.addEventListener('keydown', function (event) {
			if (event.key !== 'Escape') {
				return;
			}

			var openToggle = null;
			toggles.forEach(function (toggle) {
				if (toggle.getAttribute('aria-expanded') === 'true') {
					openToggle = toggle;
				}
			});

			if (!openToggle) {
				return;
			}

			closeAll();
			openToggle.focus();
		});
	}

	// --- Diagnostics panel (Settings_Menu::render_diagnostics_panel) -----------------
	//
	// Three actions, one shape: a button that talks to a guarded Ajax endpoint and
	// reports back INSIDE its own row — the full-width .gdpr-action-result under it for
	// sentences, the .gdpr-action-value next to the button for the number the action
	// operates on. window.ajaxurl is defined by WordPress on every admin screen.
	document.addEventListener('DOMContentLoaded', function () {
		var panel = document.getElementById('gdpr-tab-diagnostics');
		if (!panel) {
			return;
		}

		// Result box: a short verdict line (with the status dot the strip already uses),
		// the advice underneath in normal text, the machine-readable code as a small tag
		// — that is the word people paste into a support thread — and any notes as their
		// own muted lines rather than <br>-separated afterthoughts.
		function showResult(box, state, verdict, body, code, notes) {
			box.hidden = false;
			box.className = 'gdpr-action-result gdpr-result-' + state;
			box.textContent = '';

			var head = document.createElement('p');
			head.className = 'gdpr-result-verdict';
			head.textContent = verdict;
			if (code) {
				var tag = document.createElement('span');
				tag.className = 'gdpr-result-code';
				tag.textContent = code;
				head.appendChild(document.createTextNode(' '));
				head.appendChild(tag);
			}
			box.appendChild(head);

			if (body) {
				var text = document.createElement('p');
				text.className = 'gdpr-result-body';
				text.textContent = body;
				box.appendChild(text);
			}

			(notes || []).forEach(function (note) {
				var line = document.createElement('p');
				line.className = 'gdpr-result-note';
				line.textContent = note;
				box.appendChild(line);
			});
		}

		function post(fields) {
			return fetch(window.ajaxurl, {
				method: 'POST',
				credentials: 'same-origin',
				body: new URLSearchParams(fields)
			}).then(function (response) {
				return response.json();
			});
		}

		// --- Self-test ---------------------------------------------------------------
		var testButton = document.getElementById('gdpr-self-test-btn');
		var testResult = document.getElementById('gdpr-self-test-result');
		if (testButton && testResult) {
			testButton.addEventListener('click', function () {
				var label = testButton.textContent;
				testButton.disabled = true;
				testButton.textContent = testButton.getAttribute('data-running') || 'Testing…';
				showResult(testResult, 'running', testButton.textContent, '', '', []);

				post({ action: 'gdpr_pow_self_test', security_nonce: testButton.getAttribute('data-nonce') || '' })
					.then(function (json) {
						var payload = (json && json.data) ? json.data : {};
						if (!json || json.success !== true) {
							showResult(testResult, 'problem', payload.message || testButton.getAttribute('data-failed'), '', '', []);
							return;
						}
						var ok = payload.verdict === 'ok';
						showResult(
							testResult,
							ok ? 'ok' : 'problem',
							ok ? testButton.getAttribute('data-verdict-ok') || 'Everything works' : testButton.getAttribute('data-verdict-problem') || 'Something is wrong',
							payload.message || '',
							payload.code || '',
							payload.notes
						);
					})
					.catch(function () {
						showResult(testResult, 'problem', testButton.getAttribute('data-failed') || 'The test could not be run.', '', '', []);
					})
					.then(function () {
						testButton.disabled = false;
						testButton.textContent = label;
					});
			});
		}

		// --- The two resets, one of them two-step -------------------------------------
		//
		// Releasing the repeat-sender lock frees every held value at once. That does not
		// warrant a modal (nothing is lost, the lock refills), but it does warrant one
		// deliberate second click with the actual number in it — sitting as it does right
		// next to a harmless counter reset.
		panel.querySelectorAll('[data-diag-run]').forEach(function (button) {
			var row = button.closest('.gdpr-action-row');
			var result = row.querySelector('.gdpr-action-result');
			var value = row.querySelector('.gdpr-action-value');

			function run() {
				var label = button.textContent;
				button.disabled = true;

				post({
					action: 'gdpr_pow_diag_task',
					task: button.getAttribute('data-diag-run'),
					security_nonce: button.getAttribute('data-nonce') || ''
				})
					.then(function (json) {
						var payload = (json && json.data) ? json.data : {};
						if (!json || json.success !== true) {
							showResult(result, 'problem', payload.message || 'Failed.', '', '', []);
							button.disabled = false;
							return;
						}
						if (value && payload.value) {
							value.textContent = payload.value;
						}
						showResult(result, 'ok', payload.message || 'Done.', '', '', []);
						// Nothing left to reset — the row stays visible, the button does not.
						button.disabled = !!payload.empty;
					})
					.catch(function () {
						showResult(result, 'problem', 'The request failed. Reload the page and try again.', '', '', []);
						button.disabled = false;
					})
					.then(function () {
						button.textContent = label;
					});
			}

			// The Cancel link of a pending confirmation, so BOTH exits — cancelled and
			// carried out — can clear it. Leaving it standing after the action ran was
			// the first thing this got wrong.
			var pendingCancel = null;

			function clearConfirm() {
				delete button.dataset.confirming;
				if (pendingCancel) {
					pendingCancel.remove();
					pendingCancel = null;
				}
			}

			button.addEventListener('click', function () {
				var question = button.getAttribute('data-confirm');
				if (!question || button.dataset.confirming === '1') {
					clearConfirm();
					run();
					return;
				}

				var original = button.textContent;
				button.dataset.confirming = '1';
				button.textContent = button.getAttribute('data-confirm-yes') || 'Confirm';
				showResult(result, 'ask', question, '', '', []);

				var cancel = document.createElement('button');
				cancel.type = 'button';
				cancel.className = 'button-link gdpr-confirm-cancel';
				cancel.textContent = button.getAttribute('data-confirm-no') || 'Cancel';
				button.parentNode.insertBefore(cancel, button.nextSibling);
				pendingCancel = cancel;

				function reset() {
					clearConfirm();
					button.textContent = original;
					result.hidden = true;
					document.removeEventListener('keydown', onKey);
				}
				function onKey(event) {
					if (event.key === 'Escape') {
						reset();
					}
				}
				cancel.addEventListener('click', reset);
				document.addEventListener('keydown', onKey);
				// Confirming (not cancelling) must drop the key handler too, or every
				// later Escape would try to reset a button that is long done.
				button.addEventListener('click', function once() {
					document.removeEventListener('keydown', onKey);
					button.removeEventListener('click', once);
				});
			});
		});

		// --- Deep link from the message detail view (…#gdpr-self-test) -----------------
		//
		// The anchor lives in a hidden panel now, so jumping to it would land on nothing.
		// Open the panel first, then let the browser scroll (scroll-margin-top handles
		// the admin bar). Without this the link fails SILENTLY, which is the worst way.
		if (window.location.hash) {
			var target = document.querySelector(window.location.hash);
			var hiddenPanel = target && target.closest('.gdpr-tab-panel[hidden]');
			if (hiddenPanel) {
				var pill = document.querySelector('.gdpr-pill-tab[data-tab-target="' + hiddenPanel.id + '"]');
				if (pill) {
					pill.click();
					target.scrollIntoView();
				}
			}
		}
	});
})();
