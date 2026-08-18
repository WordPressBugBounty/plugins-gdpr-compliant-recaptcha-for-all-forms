<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Options: Options-Matrix, Teil 1 — die Reiter "Most relevant" und
 * "Spam Processing": welche Einsendungen ueberhaupt bewertet werden und was mit
 * erkanntem Spam geschieht.
 *
 * SCHNITTLINIE (Welle 3, PLAN-DATEIGROESSE.md): Settings_Menu war eine Datei mit
 * 2592 Zeilen. Sie ist entlang ihrer Sektionen aufgeteilt:
 *   - class-settings-menu.php             — Konstruktion, Hooks, Menue, Selbsttest,
 *                                           prepare_options() und der Proxy-Vorschlag.
 *   - trait-settings-defaults.php         — die drei get_default_*()-Seeds (handbuch/gate.md).
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
trait Settings_Options {
	/**
	 * Options-Matrix, Teil 1: die Reiter "Most relevant" und "Spam Processing".
	 *
	 * Der Schnitt liegt auf einer REITER-Grenze, nicht irgendwo: die Einfuegereihenfolge
	 * dieses Arrays IST die Reiter-Reihenfolge der Seite (get_groups()), eine Umsortierung
	 * waere also sichtbar. Deshalb zwei zusammenhaengende Haelften statt einer thematischen
	 * Neugruppierung.
	 *
	 * @return Option[]
	 */
	private function options_detection_and_spam() {
		$text_block = __(
			'Once enabled, submissions that the spam check classifies as spam are rejected outright instead of being passed on to your form or mailer.<br><br>Turn this off if you would rather let every submission through and rely only on flagging (see <b>Flag spam messages</b> 🚩) or manual review in the spam inbox.',
			'gdpr-compliant-recaptcha-for-all-forms'
		);

		$text_flag = __(
			'<strong>How it works:</strong> Instead of blocking spam messages, this option lets them through but marks them, so you can still receive every submission by mail while sorting spam into a separate folder client-side.
<br>
<br><strong>Use this if:</strong> your messages are routed to your email address and you want to receive all of them, but with spam ones flagged so your mail program can move them to a spam folder automatically.
<br>
<br>To flag spam in a specific field or a newly created field instead of blocking it:
<br><ul>
        <li>disable <b>Block spam</b> ⛔</li>
        <li>and either maintain <b>Fieldname:prefix to flag spam _*</b>, to signal spam via an existing technical field</li>
        <li>or maintain <b>New "POST" field to flag spam +</b>, to signal spam via a brand-new technical field</li>
    </ul>',
			'gdpr-compliant-recaptcha-for-all-forms'
		);

		$text_flag_suffixes = sprintf(
			/* translators: 1: opening anchor tag linking to the message inbox, 2: closing anchor tag */
			__(
				"<strong>How it works:</strong> The flagging works by adding a prefix (e.g. <code>[spam]</code>) to the value of a chosen field (e.g. a subject field) from a specific form.
<br>In your email client you can use this prefix to create a rule that moves flagged mails into a spam folder.
<br>
<br><strong>Example:</strong>
<br><ul>
        <li>the subject <code>New contact request</code>,</li>
        <li>submitted with the field <code>subject</code> of the contact form,</li>
        <li>is changed to <code>[spam]New contact request</code></li>
        <li>if the submission is classified as spam.</li>
    </ul>
<br><strong>Finding the field name:</strong> Enter the combination of field name and prefix into this textbox. The field name has to be the specific technical field name of the message you want to flag. If you don't know it, you can find it this way:
    <br><ol>
        <li>Tick the box for 'Save clean messages'.</li>
        <li>Post a message from the respective form.</li>
        <li>Open the %1\$sMessage inbox%2\$s and the just-received message.</li>
        <li>Look for the field you want to use for flagging and take the name of the respective attribute, without quotes.</li>
        <li>If the field name is nested, it may look a bit confusing (example: <code>wpforms->fields->0->first</code>). This happens when your form builder uses a nested field structure — the field name reflects that structure. Copy the whole field name without the trailing colon.</li>
    </ol>
<br><strong>Format:</strong> <code>fieldname:prefix</code>
<br>
<br><strong>Examples:</strong>
<br><code>prename:spam</code>
<br><code>wpforms->fields->0->first:[spam]</code>
<br>
<br><strong>Multiple fields:</strong> To add different flags to different technical fields, enter a new line for each combination of field name and prefix. This helps when different sources of submissions use different technical field names.",
				'gdpr-compliant-recaptcha-for-all-forms'
			),
			'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES . '">',
			'</a>'
		);
		return array(
			Option::POW_DIRECT_ANALYSIS_MODE => new Option(
				__( 'Direct analysis mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				sprintf(
					__(
						'<strong>How it works:</strong><br>
                    Once activated...<br>
                    <ol>
                        <li>Navigate to the pages containing your forms.</li>
                        <li>Submit the forms you want to add to the spam check.</li>
                        <li>Enhance the spam check directly from your pages.</li>
                        <li>Follow the additional instructions shown on the forms.</li>
                        <li>Finally, remember to deactivate the mode.</li>
                    </ol>',
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🕵️',
				__( 'Adds an inline helper to your live forms so you can teach the spam check about them without leaving the page.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ANALYSIS_MODE        => new Option(
				__( 'Analysis mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				sprintf(
					/* translators: 1: URL to the Analytic Box (inline mention), 2: URL to the Analytic Box (step-by-step link) */
					__(
						"<strong>Why you might need this:</strong> If you cannot see specific submissions in the messages or spam inbox, enable analysis mode. Many types of POST submissions belong to technical background processes and are ignored by the spam check, which by default only runs on WordPress's standard submission routine — but many form builders and other plugins use proprietary submission methods.
                    <br>
                    <br><strong>How it works:</strong> In this mode, every type of POST submission is saved into the <a href='%1\$s'>Analytic Box</a>, a further inbox of this plugin used to widen the scope of the spam check.
                    <br><br>
                    <ol>
                        <li>Submit the specific form type you want the spam check to cover.</li>
                        <li>Visit the <a href='%2\$s'>Analytic Box</a> and look for the message related to your submission (usually one of the latest).</li>
                        <li>For a Non-Ajax-Request message, choose the field/value combination that identifies it. If a future message matches all chosen attributes and values, the spam check will cover it too — pick as few pattern elements as possible. Example: to recognize Contact Form 7, <code>_wpcf7</code> is enough, since virtually all its submissions include that key.</li>
                        <li>Click the button at the bottom of the message to register the pattern or action.</li>
                        <li>A single form submission can sometimes trigger multiple separate requests, each producing its own message in the Analytic Box — register all of them if applicable.</li>
                        <li>Disable <b>Analysis mode</b> 🔍 to stop recording.</li>
                    </ol>",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS,
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔍',
				__( 'Records every incoming POST submission so you can add unrecognized form types to the spam check.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_EXPLICIT_ACTION      => new Option(
				__( 'Apply on actions', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				self::get_default_ajax_actions(),
				sprintf(
					/* translators: 1: opening anchor tag linking to the message inbox, 2: closing anchor tag, 3: URL to the Analytic Box */
					__(
						"Add one action per line that you want the spam protection to cover while the plugin is in <b>Explicit mode</b> 🎯.
                        <br>You can find and copy the action from unwanted messages in the plugin's %1\$sspam or message inbox%2\$s, or use <b>Analysis mode</b> 🔍 to record all types of submissions: open the <a href='%3\$s'>Analytic Box</a>, search for the related message and register its action from the button at the bottom of that message.
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><code>forminator_submit_form_custom-forms</code>
                        <br><code>wpforms_submit</code>",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES . '">',
					'</a>',
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⚙️✔️',
				__( 'Names the specific AJAX/form actions that the spam check should apply to when running in Explicit mode.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_PARAMETER_PATTERN    => new Option(
				__( 'Apply on pattern', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				self::get_default_recognition_patterns(),
				sprintf(
					/* translators: 1: opening anchor tag linking to the Analytic Box, 2: closing anchor tag */
					__(
						'<strong>Why you might need this:</strong> If your form submissions are not filtered by the spam check, the most likely reason is that this submission type is not yet recognized by it.
                    <br>
                    <br><strong>How it works:</strong> You can insert and view parameter patterns here directly, but the easiest way is to enable <b>Analysis mode</b> 🔍, submit the form you want covered, and search the %1$sAnalytic Box%2$s for the related message.
                    Open it, choose the fields and values that identify your pattern, and add the pattern via the button at the bottom of the message.
                    <br>Added patterns are listed here line by line, in JSON format, and can be edited directly. One line is one rule, and a submission only has to match a single line to be checked. Name as few fields as possible — just enough to recognize the form.
                    <br>
                    <br><strong>Example:</strong>
                    <br>
                    <br><code>{"_wpcf7":null}</code>
                    <br><code>{"form_id":"7"}</code>
                    <br><code>{"my_form":null,"step":"2"}</code>
                    <br>
                    <br><code>null</code> as the value means <em>this field only has to be present</em>, whatever it contains — that is the usual case, and one field name is often enough for a whole form builder (every Contact Form 7 submission carries <code>_wpcf7</code>). Writing a value instead narrows it to submissions where that field holds exactly that value, e.g. one single form rather than all of them — keep the quotation marks around it even when the value is a number, as in the example above. Naming several fields in one line means all of them must match.
                    <br>
                    <br><strong>Matching by value, whatever the field is called:</strong> <code>{"*":"value"}</code> matches when ANY field carries this value — useful when the field name differs between submissions. Like every other line here it only makes the submission get CHECKED; to treat a value as spam outright, use <b>Blocked values</b> 🚫 instead.',
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS . '">',
					'</a>'
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔍✔️',
				__( 'Defines field/value patterns that identify a submission type so the spam check applies to it.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_REST_ROUTES          => new Option(
				__( 'Apply on REST routes', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				self::get_default_rest_routes(),
				__(
					'<strong>Why you might need this:</strong> Some form builders submit over the WordPress REST API instead of a classic POST or AJAX call, and carry neither an <b>Apply on actions</b> ⚙️✔️ value nor an <b>Apply on pattern</b> 🔍✔️ match — this list is what covers them.
                    <br>
                    <br><strong>How it works:</strong> Add one REST route per line. A leading slash is optional. Two wildcard forms are supported:
                    <br><ul>
                        <li><code>*</code> as one segment matches exactly that segment, e.g. a form ID: <code>contact-form-7/v1/contact-forms/*/feedback</code></li>
                        <li><code>*</code> as the LAST segment matches the whole namespace below it, e.g. <code>ws-form/v1/*</code></li>
                    </ul>
                    <br><strong>Never add a bare core namespace like <code>wp/v2</code></strong> — that would also match the block editor\'s own save requests and block your own post saves.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🧭✔️',
				__( 'Names the REST API routes that the spam check should apply to, for builders that submit over REST.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_BLOCK_LOGIN          => new Option(
				__( 'Apply for WordPress-Login', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__(
					'This option improves site security a lot.
                    <br>
                    <br><strong>Test first:</strong> enable <em>Simulate spam messages</em> before switching this on for a live site — it lets you verify nothing legitimate gets locked out.
                    <br>
                    <br><strong>But beware:</strong> for any plugin that secures the WP login, only use this if you know how to switch it off without logging in (e.g. by deleting the plugin files from your plugin directory). If anything goes wrong, the plugin will block your login too.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔒',
				__( 'Applies the proof-of-work check to the WordPress login form in addition to your other forms.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_BLOCK                => new Option(
				__( 'Block spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				$text_block . '<br><br><strong>Test first:</strong> ' . __( 'enable <em>Simulate spam messages</em> before switching this on for a live site — it lets you verify nothing legitimate gets blocked.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⛔', // Blocking
				__( 'Blocks submissions classified as spam instead of letting them through.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_BLOCKED_VALUES       => new Option(
				__( 'Blocked values', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'<strong>What this does:</strong> a submission that matches any line here is treated as spam right away, no further check involved — regardless of which form it came through.
                    <br>Add one value per line, in one of four forms:
                    <br><ul>
                        <li>A field equals this text, word for word: <code>buy cheap pills</code></li>
                        <li>An email address found in the message equals this address: <code>spammer@example.com</code></li>
                        <li>Domain of a link found anywhere in the message text: <code>spam-shop.tld</code></li>
                        <li>Sender domain, everything after the @: <code>@disposable.tld</code> — matches that domain and all of its subdomains</li>
                    </ul>
                    <br>
                    <br><strong>Example:</strong>
                    <br>
                    <br><code>spammer@example.com</code>
                    <br><code>@disposable.tld</code>
                    <br><code>casino-bonus.tld</code>
                    <br><code>buy cheap pills</code>
                    <br>
                    <br>Values are compared after trimming spaces and ignoring upper/lower case, so <code>Spammer@Example.com</code> is the same entry. A plain line matches the value itself, never a part of a word.
                    <br>For the three address and domain forms you rarely need to type anything: open the message in your inbox and use its <b>Block this sender</b>, <b>Block this domain</b> or <b>Block this sender\'s domain</b> button, which writes the correct line for you.
                    <br>
                    <br><strong>Only one field, or only one form:</strong> a line that starts with <code>{</code> is a rule. It lists field names and the value each must carry, and it blocks only when <em>all</em> of them hold. The value is compared in the same four forms as above.
                    <br><ul>
                        <li><code>{"your-email":"@gmail.com"}</code> — only when that address field is a Gmail address; a Gmail address written in the message text is left alone</li>
                        <li><code>{"_wpcf7":"123","your-email":"@gmail.com"}</code> — the same, but only on the form with that id</li>
                        <li><code>{"message":"casino-bonus.tld"}</code> — that domain only when it is linked in the message, not when a customer types it into the website field</li>
                        <li><code>null</code> instead of a value means the field only has to be there: <code>{"_wpcf7":null,"message":"casino-bonus.tld"}</code></li>
                    </ul>
                    <br>A rule narrows <em>where</em> a value is looked for, not <em>what</em> counts as a hit: the value is still compared in the four forms above, never as a part of a word.
                    <br>A value is always compared as text here, so the quotation marks around a number are optional: <code>{"phone":12345}</code> and <code>{"phone":"12345"}</code> are the same rule. (In <b>Apply on pattern</b> 🧭 they are <em>not</em> — a pattern compares types as well, and an unquoted number there matches nothing.) An empty value, though, matches nothing at all: if you mean <em>this field only has to be there</em>, write <code>null</code> rather than <code>""</code>.
                    <br>The field name is the one your form actually sends (see a stored message\'s detail view); the form id field differs per builder (<code>_wpcf7</code>, <code>wpforms[id]</code> …). A rule that names <em>only</em> a form and pins no value — <code>{"_wpcf7":null}</code> — blocks every submission of that form, so it is held back once and asks you to confirm. If you meant to <em>watch</em> a form rather than block it, that line belongs in <b>Apply on pattern</b> 🧭 instead.
                    <br><strong>Careful with the sender-domain form:</strong> if <b>Apply for WordPress-Login</b> 🔒 is on (the default), it also blocks logins — entering a large provider like <code>gmail.com</code> can lock out registered users, possibly yourself with no way back in. It also blocks real visitors who write to you from such an address, so keep it to disposable and spam domains. Plain lines spare registered users signing in on the WordPress login page; a rule bound to a login field does not, so do not bind one to <code>log</code> or <code>pwd</code>.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚫',
				__( 'Values that mark a submission as spam outright: sender addresses, sender domains (@domain), link domains, or exact field text — one per line, optionally bound to one field or one form.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SPAM            => new Option(
				__( 'Flag spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				$text_flag,
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚩',
				__( 'Lets spam through but marks it so your mail client can filter it into a spam folder.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SUFFIXES        => new Option(
				__( 'Fieldname:prefix to flag spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				$text_flag_suffixes,
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'_*',
				__( 'Adds a text prefix such as [spam] to a chosen field when a message is flagged as spam.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_TAGS            => new Option(
				__( 'New "POST" field to flag spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					"<strong>Use this if:</strong> you want to flag spam via a brand-new POST field instead of a prefix. This field can then be used during further processing (e.g. a mailer, database routines, a mail client, ...).
                <br>
                <br><strong>Beware:</strong> this option overrides existing post fields with the same name, which may affect further processing. If you want to be sure not to override an existing field, check the technical field names of your messages first, as described for the prefixes above.
                <br>
                <br><strong>How it works:</strong> For each combination of <code>field:value</code>, add a new line. If different follow-up processes require different fields to flag spam, add multiple lines.
                <br>
                <br><strong>Example:</strong> <code>spam_filter:spam</code>
                <br>
                <br>Applying this rule, a flagged spam message with the attributes ...
                <br>
                <br><code>{'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', 'message':'Hi there'}</code>
                <br>
                <br>... would turn into ...
                <br>
                <br><code>{'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', 'message':'Hi there', 'spam_filter':'spam'}</code>",
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'+',
				__( 'Adds a brand-new field with a fixed value to messages that are flagged as spam.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ERROR_MESSAGE        => new Option(
				__( 'Error message', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::STRING,
				__( 'Your message has been classified as spam! If you are a human, we are very sorry. Please give us notice via email.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__(
					"
                    Usually visitors will never see this message, but if anything goes wrong, this is your chance to give them some meaningful advice.
                    <br>
                    <br>For some form builders or other relevant plugins, the error message won't pop up, since each plugin uses its own display format.
                ",
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'❌',
				__( 'Sets the message shown to visitors on the frontend when their submission is blocked as spam.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SIMULATE_SPAM        => new Option(
				__( 'Simulate spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'If checked, every incoming submission is treated as spam, so you can verify that blocking and flagging work as intended before relying on them for real traffic. It is not applied to the WordPress login.<br><br><strong>Beware:</strong> do not forget to uncheck this option once your testing is done.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📈',
				__( 'Treats every incoming submission as spam so you can safely test blocking and flagging before going live.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FAIL_2_BAN_PATH      => new Option(
				__( 'Path to save spam approaches to syslog', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'<strong>The purpose:</strong> <br>Fail2Ban is a security tool designed to <strong>protect servers</strong> by monitoring log files and automatically blocking IP addresses involved in <strong>repeated unauthorized access attempts or suspicious activity</strong>.
                            <br>While commonly used for <strong>SSH, email servers, and web applications</strong>, this integration focuses on securing WordPress forms from login abuse and spam.<br>

                            <br><strong>Specify the directory path where log files should be stored:</strong>
                            <ul>
                            <li>If the field is <strong>left empty or contains an invalid path</strong>, logging remains <strong>disabled</strong>.</li>
                            <li>A <strong>valid directory path</strong> enables logging, generating two separate log files:
                                <ul>
                                <li><strong>Login attempts log:</strong> <code>auth.log</code> — records failed login attempts.</li>
                                <li><strong>Spam detection log:</strong> <code>spam.log</code> — logs suspicious form submissions.</li>
                                </ul>
                            </li>
                            </ul>

                            <br>Ensure the specified path is <strong>writable</strong> by the server and does not include a filename, as logs are managed automatically within the chosen directory.
                            <br>If <code>auth.log</code> or <code>spam.log</code> already exist in the specified directory, they are reused instead of creating new files.<br>',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛡',
				__( 'Writes failed logins and spam attempts to log files that tools like Fail2Ban can monitor.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
		);
	}
}
