<?php
/**
 * Der Klassen-Loader des Plugins: WELCHE Dateien es gibt und in welcher REIHENFOLGE sie
 * geladen werden. Kein Autoloader, also steht hier jede Datei einzeln — eine neue Datei
 * unter `plugin/includes/` braucht ihre Zeile hier, sonst existiert ihre Klasse nicht.
 *
 * SCHNITTLINIE (PLAN-DATEIGROESSE.md). Der Block stand bis 5.6.0 im Rumpf von
 * `Recaptcha_Gdpr_Compliant::get_instance()` und war dort der einzige Teil, der bei JEDER
 * neuen Klasse mitwuchs — die Bootstrap-Datei lief damit strukturell auf ihren Deckel zu,
 * ohne dass sich an ihrer eigentlichen Aufgabe (Lebenszyklus, Hooks, Aktivierung) etwas
 * geaenderte. Der Schnitt trennt genau das: hier steht, was es gibt; dort steht, was damit
 * passiert.
 *
 * VERSCHOBEN, NICHT UMGESCHRIEBEN. Die Reihenfolge ist unveraendert und bleibt tragend —
 * Traits vor der Klasse, die sie einbindet. Nur die Pfade sind um `includes/` kuerzer,
 * weil `__DIR__` jetzt dieses Verzeichnis ist.
 *
 * Wird aus `get_instance()` heraus eingebunden, also erst wenn das Plugin wirklich
 * hochfaehrt, und dank `require_once` genau einmal.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Die ausgelagerte Zaehl-Haelfte von Option (Welle 4, PLAN-DATEIGROESSE.md).
require_once __DIR__ . '/trait-option-counters.php';
require_once __DIR__ . '/class-option.php';
require_once __DIR__ . '/class-proof-of-work.php';
// Die ausgelagerte Blocklisten-Haelfte von Echo_Values (Welle 4, s.u.).
require_once __DIR__ . '/trait-blocklist-values.php';
require_once __DIR__ . '/class-echo-values.php';
require_once __DIR__ . '/class-echo-store.php';
// Die zwei ausgelagerten Haelften von Message_Page (Welle 3, PLAN-DATEIGROESSE.md).
// GILT FUER JEDE trait-*.php-Zeile hier: Traits werden zur Kompilierzeit in die
// Klasse kopiert, muessen also VOR ihrer Klassendatei stehen — sonst Fatal Error.
require_once __DIR__ . '/trait-message-actions.php';
require_once __DIR__ . '/trait-message-gibberish.php';
require_once __DIR__ . '/trait-message-script-data.php';
require_once __DIR__ . '/trait-message-list.php';
require_once __DIR__ . '/class-message-page.php';
require_once __DIR__ . '/class-client-ip.php';
require_once __DIR__ . '/class-proxy-candidate-ledger.php';
require_once __DIR__ . '/class-rest-route.php';
require_once __DIR__ . '/class-stamp-token.php';
require_once __DIR__ . '/class-gibberish-detector.php';
require_once __DIR__ . '/class-gibberish-fields.php';
require_once __DIR__ . '/class-gibberish-signature.php';
require_once __DIR__ . '/class-gibberish-notice.php';
require_once __DIR__ . '/class-opcache.php';
require_once __DIR__ . '/class-classification-reason.php';
require_once __DIR__ . '/class-credential-fields.php';
require_once __DIR__ . '/class-learned-credential-fields.php';
require_once __DIR__ . '/class-credential-suggestion-ledger.php';
require_once __DIR__ . '/class-credential-learning.php';
require_once __DIR__ . '/class-credential-cleanup.php';
require_once __DIR__ . '/class-blocked-values-migration.php';
require_once __DIR__ . '/class-pattern-matcher.php';
// Die zwei ausgelagerten Haelften von Overbroad_Pattern_Guard (Welle 4).
require_once __DIR__ . '/trait-overbroad-blame.php';
require_once __DIR__ . '/trait-overbroad-save-warning.php';
require_once __DIR__ . '/class-overbroad-pattern-guard.php';
// Die zwei ausgelagerten Haelften von Stamp (PLAN-DATEIGROESSE.md) — Traits vor der Klasse.
require_once __DIR__ . '/class-field-envelopes.php';
require_once __DIR__ . '/trait-stamp-capture.php';
require_once __DIR__ . '/trait-stamp-persistence.php';
require_once __DIR__ . '/trait-stamp-triage.php';
require_once __DIR__ . '/class-stamp.php';
// Support-Report (Diagnostics-Reiter): liest Option/ProofOfWork/Stamp/Echo_Store,
// muss also nach allen vieren stehen.
require_once __DIR__ . '/class-support-report.php';
// Die acht ausgelagerten Sektionen von Settings_Menu (Welle 3, PLAN-DATEIGROESSE.md;
// die drei get_default_*()-Seeds seit PLAN-BUILDER-SEED.md Phase 3 weiter aufgeteilt).
require_once __DIR__ . '/trait-settings-default-actions.php';
require_once __DIR__ . '/trait-settings-default-patterns.php';
require_once __DIR__ . '/trait-settings-default-routes.php';
require_once __DIR__ . '/trait-settings-options.php';
require_once __DIR__ . '/trait-settings-options-storage.php';
require_once __DIR__ . '/trait-settings-status.php';
require_once __DIR__ . '/trait-settings-save.php';
require_once __DIR__ . '/trait-settings-page.php';
require_once __DIR__ . '/class-settings-menu.php';
require_once __DIR__ . '/class-scope-sync.php';
require_once __DIR__ . '/class-scope-add.php';
require_once __DIR__ . '/class-agent-access.php';
require_once __DIR__ . '/class-ability-probe.php';
// Die ausgelagerten Execute-Callbacks von Abilities (Welle 4, PLAN-DATEIGROESSE.md).
require_once __DIR__ . '/trait-ability-actions.php';
require_once __DIR__ . '/class-abilities.php';
require_once __DIR__ . '/class-dashboard-widget.php';
require_once __DIR__ . '/class-analysis.php';
