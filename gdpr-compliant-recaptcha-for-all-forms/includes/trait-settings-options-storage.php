<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Options_Storage: Options-Matrix, Teil 2 — die Reiter
 * "Saving Messages", "Scope", "WordPress Administration", "Algorithm" und
 * "AI & Agents": alles, was nicht die Spam-Entscheidung selbst ist.
 *
 * SCHNITTLINIE (Welle 3, PLAN-DATEIGROESSE.md): Settings_Menu war eine Datei mit
 * 2592 Zeilen. Sie ist entlang ihrer Sektionen aufgeteilt:
 *   - class-settings-menu.php             — Konstruktion, Hooks, Menue, Selbsttest,
 *                                           prepare_options() und der Proxy-Vorschlag.
 *   - trait-settings-default-actions.php  — get_default_ajax_actions() (handbuch/gate.md).
 *   - trait-settings-default-patterns.php — get_default_recognition_patterns() (handbuch/gate.md).
 *   - trait-settings-default-routes.php   — get_default_rest_routes() (handbuch/gate.md).
 *   - trait-settings-options.php          — Options-Matrix, Teil 1 (Reiter "Most relevant",
 *                                           "Spam Processing").
 *   - trait-settings-options-storage.php  — Options-Matrix, Teil 2 (Reiter "Saving Messages",
 *                                           "Scope", "WordPress Administration", "Algorithm",
 *                                           "AI & Agents").
 *   - trait-settings-status.php           — Status-Leiste und die Proxy-Hinweise darunter.
 *   - trait-settings-save.php             — update_settings(), die Persistenz samt Save-Guards.
 *   - trait-settings-page.php             — das Rendern der Seite (Tabs, Karten, Diagnose).
 *
 * Traits statt zweiter Klassen, und zwar bewusst: diese Methoden sind als
 * `array( $this, ... )`-Hooks registriert, lesen `$this->options`/`$this->plugin_name`
 * und die request-scoped `$pending_*`-Felder, und mehrere Quelltext-Pins in tests/unit
 * haengen an genau dieser Bindung. Ein Trait wird zur Kompilierzeit in die Klasse
 * kopiert — die Aufteilung ist damit ein Umzug, kein Umbau, und kein Aufrufer,
 * kein Hook und keine Sichtbarkeit aendert sich.
 */
trait Settings_Options_Storage {
	/**
	 * Options-Matrix, Teil 2: die Reiter "Saving Messages", "Scope",
	 * "WordPress Administration", "Algorithm" und "AI & Agents".
	 *
	 * Warum hier geschnitten: s. options_detection_and_spam().
	 *
	 * @return Option[]
	 */
	private function options_storage_and_setup() {
		$pow_save_spam_label = sprintf(
			/* translators: %s: URL to the spam inbox page */
			__(
				"You can review your saved spam messages <a href='%s'>here</a>.",
				'gdpr-compliant-recaptcha-for-all-forms'
			),
			admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_SPAM
		);

		return array(
			Option::POW_SAVE_CLEAN                 => new Option(
				__( 'Save clean messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				sprintf(
					/* translators: %s: URL to the message inbox page */
					__( "You can review your saved clean messages <a href='%s'>here</a>.", 'gdpr-compliant-recaptcha-for-all-forms' ),
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES
				),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'💾',
				__( 'Stores non-spam submissions in the message inbox so you can review them later.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_SPAM                  => new Option(
				__( 'Save spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				$pow_save_spam_label,
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'💾',
				__( 'Stores submissions classified as spam in the spam inbox so you can review them later.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_LOGIN                 => new Option(
				__( 'Save Logins', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( "Disable this option if you don't want submissions from the WordPress login and password-reset forms to be recorded. Analysis Mode is the one exception — while it is on, it keeps capturing them for inspection.<br><br>Password values are never stored either way; they are replaced with [redacted].", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔒💾',
				__( 'Records login and password-reset submissions in the message inbox.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SAVE                  => new Option(
				__( 'Save spam messages with flag', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Controls whether spam messages are saved with their flag intact or with the flag stripped.<br><br>For testing whether flagging works as desired, it can be useful to save messages with their flags.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚩💾',
				__( 'Keeps the spam flag on messages that are saved, instead of stripping it before saving.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_IP                    => new Option(
				__( 'Save spam messages with IP', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__( "<strong>Warning:</strong> saving visitors' IP addresses does not comply with the European data privacy act <b>GDPR</b>.", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛡️💾',
				__( "Stores the submitter's IP address with saved spam messages (not GDPR-compliant).", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SKIP_FIELDS                => new Option(
				__( 'Skip fields from saving and spam analysis', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				sprintf(
					/* translators: 1: opening anchor tag linking to the message inbox, 2: closing anchor tag */
					__(
						"<strong>Use this if:</strong> you want to exclude specific fields on specific sites from being saved with messages. This is recommended for password fields, in particular.
                    <br>
                    <br><strong>How it works:</strong> Enter each combination of <code>site:field-name</code> on its own line. The field name has to be the specific technical field name, and the site name the specific technical name of the site containing it.
                    <br>If you don't know the exact technical field names and site names, you can find them this way:
                        <br><ol>
                            <li>Tick the box for 'Save clean messages'.</li>
                            <li>Save the options.</li>
                            <li>Post a message from the respective site.</li>
                            <li>Open the %1\$sMessage inbox%2\$s and the just-received message.</li>
                            <li>Look for the field you wish to skip from saving and take the name of the respective attribute, without quotes.</li>
                            <li>Look for the attribute 'from_site' to get the technical name of the site — just copy the unique part of the URL (i.e. the specific site name without the domain or any parameters).</li>
                        </ol>
                    <br><strong>Format:</strong> <code>site:field-name</code>
                    <br>
                    <br><strong>Example:</strong>
                    <br><u>Given site:</u> <code>www.your-domain.net/specific_site/?action=123</code>
                    <br><u>Given field name:</u> <code>pwd</code>
                    <br>
                    <br><u>Line to add:</u> <code>/specific_site/:pwd</code>
                    <br>
                    <br><strong>This list is only about saving.</strong> Up to version 5.6 it also excluded fields from gibberish detection; since 6.0 that is not needed, because gibberish detection only ever looks at fields you pick yourself (see <b>Gibberish detection</b> 🔤).
                    ",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES . '">',
					'</a>'
				),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚫▭',
				__( 'Excludes specific fields, such as passwords, from being saved with messages.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CREDENTIAL_FIELDS          => new Option(
				__( 'Credential fields', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					"<strong>What this is:</strong> the list of field names this plugin treats as passwords. Their values are never stored — the field still appears in a saved message, but its value reads <code>[redacted]</code>.
                    <br>
                    <br><strong>You normally do not edit this here.</strong> Common password field names are recognised automatically. When a form on your site posts a password field with an unusual name, the plugin offers to add it — as a notice at the top of your admin pages, or as a <em>Treat as credential field</em> button next to the value in a saved message. This box is the place to review, correct and remove those entries.
                    <br>
                    <br><strong>Format:</strong> one field name per line, exactly as it appears in a saved message (the part after the last <code>-&gt;</code> for nested fields). Matching is case-insensitive and applies to whole names only — an entry <code>pass</code> never matches <code>passenger</code>. Entries are NOT tied to a site: a password field name counts everywhere.
                    <br>
                    <br><strong>Adding a name here also cleans up:</strong> messages you already received are redacted retroactively, in small steps, over the following page loads.
                    <br>
                    <br><strong>Careful with:</strong> <code>email</code>, <code>name</code>, <code>subject</code> and <code>message</code>. Redacting those hides the very values you need to judge and block spam, so the plugin never suggests them.
                    <br>
                    <br><strong>Not the same as 'Skip fields from saving':</strong> that one drops a field completely and is tied to a site. This one keeps the field visible and only removes its value.",
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔑🚫',
				__( 'Field names whose values are stored as "[redacted]" — normally filled by confirming the plugin\'s own suggestions.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_MESSAGE_HEADS              => new Option(
				__( 'Subject fields', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				sprintf(
					/* translators: %s: URL to the message inbox page */
					__(
						"<strong>Use this if:</strong> you want meaningful titles on the saved messages page instead of generic ones, by customizing the subject fields per form.
                <br>
                <br><strong>How it works:</strong> Add a new line for each part of the subject. The field name has to be the specific technical field name of the message. If you don't know it, you can find it this way:
                <br>
                <br><ol>
                    <li>Tick the box for 'Save clean messages'.</li>
                    <li>Post a message from the respective form.</li>
                    <li>Open the <a href='%s'>\"Messages\" inbox</a> and open the message that was just saved.</li>
                    <li>Look for the field you want to use, and take the name of the respective attribute without quotes.</li>
                </ol>
                <br><strong>Example for a subject composed of two parts:</strong>
                <br>
                <br><code>subject</code>
                <br><code>wpforms->fields->1</code>",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES
				),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔤',
				__( 'Builds a readable subject line for saved messages from one or more submitted fields.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_CART                  => new Option(
				__( 'Save WooCommerce shopping carts', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'If you get too many messages from shopping carts, you can disable this option.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛒',
				__( 'Saves WooCommerce shopping cart activity as messages in the inbox.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_INBOX          => new Option(
				__( 'Automatic Message Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️✉️',
				__( 'Automatically deletes messages from the inbox after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_SPAM           => new Option(
				__( 'Automatic Spam Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️📩',
				__( 'Automatically deletes messages from the spam inbox after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_TRASH          => new Option(
				__( 'Automatic Trash Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️📨',
				__( 'Automatically deletes messages from the trash after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_IP_WHITELIST               => new Option(
				__( 'IP-Whitelist', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__( 'Add one IP per line, without any separator.<br><br><strong>Example:</strong><br>192.0.0.1<br>241.x.x.xxx<br>...', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🌐',
				__( 'Exempts the listed IP addresses from the spam check entirely.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SITE_WHITELIST             => new Option(
				__( 'Site-Whitelist', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'Add one site per line, without the protocol (i.e. without "https://" or "http://").
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><code>dev.whistle-blower.net/?rest_route=/jetpack/v4/verify_registration/</code>
                        <br>...',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📄',
				__( 'Exempts the listed URLs (without protocol) from the spam check entirely.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_TRUSTED_PROXIES            => new Option(
				__( 'Trusted proxies', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'One IP or CIDR range per line. Forwarded-For headers are only honored when the request comes from one of these proxies. Leave empty if your site is not behind a reverse proxy.
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><code>203.0.113.10</code>
                        <br><code>10.0.0.0/8</code>
                        <br>...',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛰️',
				__( "Lists proxy IPs allowed to supply the visitor's real IP via forwarding headers.", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_TRUST_PRIVATE_PROXY        => new Option(
				__( 'Trust a private-network proxy', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'<strong>Only has any effect while "Trusted proxies" above is empty.</strong> Once you list a proxy there, that list decides and this setting is ignored.
                        <br>
                        <br><strong>What it does:</strong> If the request reaches WordPress from a private or loopback address (10.x, 172.16-31.x, 192.168.x, 127.x, ::1), there is in practice always a reverse proxy in front of it — a hosting load balancer, a firewall, a container gateway. With this on, the X-Forwarded-For header from such a peer is believed, and your visitors are seen under their own addresses again.
                        <br>
                        <br><strong>When you want it:</strong> your host puts a proxy in front of the site but does not tell you its address, so every visitor looks like the same IP — spam counts, the IP whitelist and fail2ban all point at one address.
                        <br>
                        <br><strong>What it costs:</strong> if the genuine visitors of this site come from a private network (an intranet, a VPN-only site), then any of them can choose their own apparent address by sending that header. The IP whitelist becomes claimable, fail2ban logs the wrong address, and per-IP limits can be stepped around. On a public site reached through a proxy this does not apply; on an internal site it does.
                        <br>
                        <br>If you know your proxy address, entering it under "Trusted proxies" is always the better answer.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛰️',
				__( 'If no trusted proxy is configured and the request comes from a private address, believe its X-Forwarded-For header.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_HIDE_ACTION                => new Option(
				__( 'Hide actions', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'Add one action per line that you do not want shown in the Analytic Box of <b>Analysis mode</b> 🔍.
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><code>heartbeat</code>',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⚙️🚫',
				__( 'Hides the listed action names from the Analytic Box while Analysis mode is recording.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_HIDE_PATTERN               => new Option(
				__( 'Hide Patterns', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				sprintf(
					/* translators: 1: opening anchor tag linking to the Analytic Box, 2: closing anchor tag */
					__(
						'Manage, line by line, the patterns that you do not want shown in the Analytic Box of <b>Analysis mode</b> 🔍.
                        <br>The easiest way to add a pattern is directly from the %1$sAnalytic Box%2$s.',
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS . '">',
					'</a>'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔍🚫',
				__( 'Hides submissions matching the listed patterns from the Analytic Box.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_MENU_POSITION              => new Option(
				__( 'Messages Inbox Position', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__(
					"<strong>How it works:</strong> The default '0' places the menu in the first position. The number also has to account for WordPress's own submenu entries, so a value like '40' may in fact result in a real position of 8 — you may need to experiment with the figure to get your preferred position.
                    <br>To hide the messages inbox entirely, set this option to '-1'.",
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'WordPress Administration', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📌', //Number symbol
				__( 'Sets where the message inbox appears in the WordPress admin menu.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_DASHBOARD                  => new Option(
				__( 'Message counters on the Wordpress Dashboard', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Includes counts for messages, spam and trash (today and in total), so you can see activity at a glance without opening the inboxes.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'WordPress Administration', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📊', //Dashboard symbol
				__( 'Shows message counters as a widget on the WordPress dashboard.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SALT                       => new Option(
				__( 'Salt', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::STRING,
				hash( 'sha256', gmdate( 'Y-m-d H:i:s.u' ) ),
				__( "Set this to a random string to give some unknown salt to the puzzle. It increases security, as it can't be guessed client-side.<br><br>By default, this salt is generated as a hash from the point in time of your installation.", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔑',
				__( "Adds a secret random string to the proof-of-work puzzle so it can't be pre-computed client-side.", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_TIME_WINDOW                => new Option(
				__( 'Time Window', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				10,
				__( 'The number of minutes a hash-puzzle stays valid before it has to be computed and solved anew.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⌛',
				__( 'Sets how many minutes a generated hash-puzzle stays valid before it must be solved again.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_DIFFICULTY                 => new Option(
				__( 'Difficulty', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				14,
				sprintf(
					/* translators: %d: under-attack difficulty bonus in bits (Stamp::UNDER_ATTACK_BONUS) */
					__(
						"If you don't know about the concept of proof-of-work, don't change this.
                        <br>
                        <br><strong>Approximate number of hash guesses required per difficulty target:</strong>
                        <ul>
                            <li>Difficulty 1-4: 10</li>
                            <li>Difficulty 5-8: 100</li>
                            <li>Difficulty 9-12: 1,000</li>
                            <li>Difficulty 13-16: 10,000</li>
                            <li>Difficulty 17-20: 100,000</li>
                            <li>Difficulty 21-24: 1,000,000</li>
                            <li>Difficulty 25-28: 10,000,000</li>
                            <li>Difficulty 29-32: 100,000,000</li>
                        </ul>
                        Modern browsers solve the puzzle via crypto.subtle, which is roughly 10x faster than the plain-JavaScript fallback used by older browsers.
                        <br>
                        <br><strong>Recommended base: 15–16.</strong> Under-attack mode temporarily adds %d bits on top of your base difficulty, so the value you set here is what every visitor pays in normal operation — the table above shows what each step costs them.
                        <br>
                        <br>Every visitor solves exactly one puzzle at the difficulty you set here. Earlier versions could hand out a second, harder puzzle when a solve looked implausibly fast; that was removed, because how long a solve takes says nothing reliable about who solved it.",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					Stamp::UNDER_ATTACK_BONUS
				),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🧩',
				__( "Controls how much computing power a visitor's browser must spend solving the proof-of-work puzzle. Recommended base: 15–16, to leave headroom for the under-attack boost.", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_MAX_USES                   => new Option(
				__( 'Max submissions per solved challenge', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				10,
				__( 'Bots that replay one solution are cut off after this many submissions; raise it if legitimate visitors submit many forms in quick succession.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔁',
				__( 'Caps how many form submissions a single solved proof-of-work may be used for within the validity window.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_UNDER_ATTACK_MODE          => new Option(
				__( 'Under-attack mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Based purely on a coarse, site-wide counter — no per-visitor data is collected or stored.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚨',
				__( 'Temporarily raises the puzzle difficulty for all visitors when site-wide spam suddenly spikes (+3 bits, roughly 8x the computing time, whenever 15+ blocked/flagged submissions occur within about 10 minutes).', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_UNDER_ATTACK_QUARANTINE    => new Option(
				__( 'Under-attack quarantine', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'<strong>What it does:</strong> While a spam wave is detected (the same site-wide counter that drives under-attack mode), submissions that pass every individual check are treated like spam: they land in the spam folder for review, and your regular spam handling applies — with "Block spam" enabled they are held back instead of being delivered.
					<br>
					<br><strong>Nothing is lost:</strong> quarantined messages are never discarded — they wait in the spam folder, and you rehabilitate genuine ones from there, exactly as with any other spam. Quarantined submissions never feed the wave counter itself, so the quarantine cannot keep the wave alive on its own.
					<br>
					<br><strong>Use this if:</strong> during an attack you would rather review grey-zone messages by hand than risk a spam submission slipping through. Be aware that with "Block spam" enabled, genuine visitors submitting during a wave will also see the spam error until the wave subsides. It only ever acts while a wave is in progress.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛡️',
				__( 'During a detected spam wave, treat otherwise-clean submissions as spam and hold them in the spam folder for review. Off by default; nothing is ever lost.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ECHO_LOCK_ENABLED          => new Option(
				__( 'Repeat-sender echo lock', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__(
					'<strong>What it does:</strong> Whenever a submission is classified as spam, the echo lock briefly remembers its core values (sender email, linked domain, phone number, and the hash of a long message body) as one-way hashes with a short lifetime. A later submission carrying the same value — on <em>any</em> form and from <em>any</em> IP — is then caught as well, so a returning spammer is stopped even after switching forms or rotating addresses.
					<br>
					<br><strong>Just a bonus layer:</strong> this only <em>adds</em> to the proof-of-work check; it never replaces it. Values are stored as hashes only (never in plain text) and expire on their own after about a day and a half.
					<br>
					<br><strong>Turn it off if</strong> (rarely) you would rather not carry values over between submissions at all — for example while diagnosing a false positive. Addresses of your registered users are already excluded automatically, so this is seldom necessary. You can also release all currently held values at any time under <em>Diagnostics</em> on this page.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔁',
				__( 'Briefly remembers the core values of spam submissions (as hashes) so the same sender/domain is caught again on any form. A bonus layer over the proof-of-work; on by default.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ABILITIES_WRITE            => new Option(
				__( 'Let agents extend what is monitored', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'<strong>What it does:</strong> With this on, an AI agent acting as a logged-in administrator can add form actions, field patterns and REST routes to the monitored scope — the same three lists you edit under <em>Recognition</em>. This is what makes it possible for an agent to notice an unprotected form and connect it up for you.
					<br>
					<br><strong>What it cannot do:</strong> entries are only ever added, never removed, and the agent cannot touch anything you added yourself. Entries that would make the plugin evaluate WordPress\' own admin traffic are refused outright, as are patterns built only from generic field names, and patterns that block senders rather than monitor forms.
					<br>
					<br><strong>What you take on:</strong> a badly chosen entry makes the plugin evaluate requests it should not, which shows up as genuine submissions being treated as spam. Every change is recorded, and you can review and undo all of it under <em>Recognition</em>. Off by default.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'AI & Agents', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🤖',
				__( 'Let an AI agent add form actions, field patterns and REST routes to the monitored scope. Only ever adds, never removes. Off by default.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ABILITIES_READ_SUBMISSIONS => new Option(
				__( 'Let agents read stored submissions', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'<strong>What it does:</strong> an AI agent acting as a logged-in administrator may list and read the submissions in your inbox and spam folder — the same entries you see on the Messages screen, with password fields redacted.
					<br>
					<br><strong>What it costs:</strong> an agent usually runs on an external AI service. This plugin still contacts nobody on its own, but with this on, what your visitors typed into your forms can be read by whatever agent you connect, and it stops being this plugin alone that decides where that content goes. What your agent does with it is yours to answer for, including under data-protection law.
					<br>
					<br><strong>What it deliberately does not open:</strong> the analysis folder. Analysis mode records every POST on the site while it runs, including admin screens of other plugins — so those entries can contain API keys and passwords that were never meant for a form. They stay unreadable here.
					<br>
					<br>Reading only. Changing or deleting anything needs the separate setting below. While this is on, a notice stays visible in your admin area. Off by default.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'AI & Agents', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⚠️',
				__( 'Let an AI agent read stored submissions. Submitted content can leave your site through the agent. Off by default.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ABILITIES_UNSAFE           => new Option(
				__( 'Let agents change protection and delete submissions', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'<strong>Leave this off unless you know why you need it.</strong> It is the one setting here that lets something other than you undo the protection.
					<br>
					<br><strong>What it does:</strong> an AI agent acting as a logged-in administrator may change three settings — the puzzle difficulty, whether spam is blocked, and under-attack mode — and permanently delete individual submissions.
					<br>
					<br><strong>What it cannot do, on purpose:</strong> everything else. It cannot touch the trusted-proxy or whitelist settings, the monitored scope, spam simulation, whether spam is stored at all, the secret behind the puzzles — or these agent permissions themselves. An agent must not be able to widen its own rights.
					<br>
					<br>The difficulty is also bounded (8–25): unbounded, a single call could set a value no browser can solve and lock out every real visitor.
					<br>
					<br>Every change and every deletion is written to an audit trail with the previous value, so you can see what happened and put it back. While this is on, a notice stays visible in your admin area. Off by default.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'AI & Agents', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⚠️',
				__( 'Let an AI agent change three protection settings and delete submissions. It can never change its own permissions. Off by default.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
		);
	}
}
