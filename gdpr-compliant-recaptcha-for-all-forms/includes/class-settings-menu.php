<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );
/**
 * Class Settings_Menu: Renders and saves the plugin's settings page (status strip,
 * pill tabs, option cards with help popovers — see options_page()).
 */

class Settings_Menu {

	/** String that represents the name of the plugin */
	private $plugin_name;

	/** Feld der Optionen */
	private $options;

	/** Option based action */
	const RCM_ACTION = Option::PREFIX . 'action';

	/** What to do with the action */
	const UPDATE = 'update';

	/** Action value for the "reset repeat-sender echo lock" status-strip button. */
	const RESET_ECHO = 'reset_echo';

	/** Constructor of the class
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'run' ) );
	}

	/**
	 * Display an admin notice in the backend.
	 *
	 * @param string $message The message to be displayed.
	 */
	public static function display_admin_notice( $message ) {
		if ( ! is_admin() || get_option( Option::POW_INSTALLED ) ) {
			return;
		}
		add_action(
			'admin_notices',
			function () use ( $message ) {
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $message ) . '</p></div>';
			}
		);
	}

	public static function get_default_ajax_actions() {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$actions           = array();
		$installed_plugins = get_plugins();
		$installed_themes  = wp_get_themes();

		// *** Thrive Architect Forms (custom submission method) ***
		if ( array_key_exists( 'thrive-architect/thrive-architect.php', $installed_plugins ) ) {
			$actions[] = 'tve_api_form_submit';
			self::display_admin_notice( __( 'Thrive Architect detected – added action: tve_api_form_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Forminator (uses WordPress AJAX) ***
		if ( is_plugin_active( 'forminator/forminator.php' ) || array_key_exists( 'forminator/forminator.php', $installed_plugins ) ) {
			$actions[] = 'forminator_submit_form_custom-forms';
			self::display_admin_notice( __( 'Forminator detected – added action: forminator_submit_form_custom-forms', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WPForms (uses WordPress AJAX) ***
		if ( array_key_exists( 'wpforms/wpforms.php', $installed_plugins ) || array_key_exists( 'wpforms-lite/wpforms.php', $installed_plugins ) ) {
			$actions[] = 'wpforms_submit';
			self::display_admin_notice( __( 'WPForms detected – added action: wpforms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Ninja Forms (uses WordPress AJAX) ***
		if ( array_key_exists( 'ninja-forms/ninja-forms.php', $installed_plugins ) ) {
			$actions[] = 'nf_ajax_submit';
			self::display_admin_notice( __( 'Ninja Forms detected – added action: nf_ajax_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Fluent Forms (uses WordPress AJAX) ***
		if ( array_key_exists( 'fluentform/fluentform.php', $installed_plugins ) ) {
			$actions[] = 'fluentform_submit';
			self::display_admin_notice( __( 'Fluent Forms detected – added action: fluentform_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Jetpack Forms (uses WordPress AJAX) ***
		if ( array_key_exists( 'jetpack/jetpack.php', $installed_plugins ) ) {
			$actions[] = 'jetpack_contact_form_submit';
			self::display_admin_notice( __( 'Jetpack Forms detected – added action: jetpack_contact_form_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Everest Forms (uses WordPress AJAX) ***
		if ( array_key_exists( 'everest-forms/everest-forms.php', $installed_plugins ) ) {
			$actions[] = 'everest_forms_submit';
			self::display_admin_notice( __( 'Everest Forms detected – added action: everest_forms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WS Forms (uses WordPress AJAX) ***
		if ( array_key_exists( 'ws-forms/ws-forms.php', $installed_plugins ) ) {
			$actions[] = 'ws_forms_submit';
			self::display_admin_notice( __( 'WS Forms detected – added action: ws_forms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Otter Blocks (uses WordPress AJAX) ***
		if ( array_key_exists( 'otter-blocks/otter-blocks.php', $installed_plugins ) ) {
			$actions[] = 'otter_blocks_submit';
			self::display_admin_notice( __( 'Otter Blocks detected – added action: otter_blocks_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Elementor Pro Forms (correct action) ***
		if ( array_key_exists( 'elementor-pro/elementor-pro.php', $installed_plugins ) ) {
			$actions[] = 'elementor_pro_forms_send_form';
			self::display_admin_notice( __( 'Elementor Pro Forms detected – added action: elementor_pro_forms_send_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return implode( "\n", $actions );
	}

	public static function get_default_recognition_patterns() {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$patterns          = array();
		$installed_plugins = get_plugins();
		$installed_themes  = wp_get_themes();

		// *** Contact Form 7 ***
		if ( array_key_exists( 'contact-form-7/wp-contact-form-7.php', $installed_plugins ) ) {
			$patterns[] = '{"_wpcf7":null}';
			$patterns[] = '{"wpcf7_submit":null}';
			$patterns[] = '{"wpcf7_contact_form":null}';
			$patterns[] = '{"wpcf7_file_upload":null}';
			$patterns[] = '{"wpcf7_attachment":null}';
			$patterns[] = '{"wpcf7_post_submission":null}';
			$patterns[] = '{"wpcf7_save_post":null}';
			self::display_admin_notice( __( 'Contact Form 7 detected – added default recognition patterns', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WooCommerce ***
		if ( array_key_exists( 'woocommerce/woocommerce.php', $installed_plugins ) ) {
			$patterns[] = '{"add-to-cart":null}';
			$patterns[] = '{"remove-from-cart":null}';
			$patterns[] = '{"update-cart":null}';
			$patterns[] = '{"woocommerce_checkout":null}';
			$patterns[] = '{"woocommerce_order":null}';
			$patterns[] = '{"woocommerce_payment_complete":null}';
			$patterns[] = '{"woocommerce_created_customer":null}';
			$patterns[] = '{"woocommerce_login":null}';
			$patterns[] = '{"woocommerce_review":null}';
			$patterns[] = '{"woocommerce_comment":null}';
			self::display_admin_notice( __( 'WooCommerce detected – added recognition patterns for cart, checkout, and user actions', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Gravity Forms (custom submission method) ***
		if ( array_key_exists( 'gravityforms/gravityforms.php', $installed_plugins ) ) {
			$patterns[] = '{"gform_submit":null}';
			$patterns[] = '{"gform_file_upload":null}';
			self::display_admin_notice( __( 'Gravity Forms detected – added recognition patterns for submissions and file uploads', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Divi Contact Form Module (custom submission method) ***
		if ( array_key_exists( 'Divi', $installed_themes ) ) {
			$patterns[] = '{"et_pb_contactform_submit_0":null}';
			self::display_admin_notice( __( 'Divi detected – added recognition pattern: {"et_pb_contactform_submit_0":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Thrive Leads & Thrive Architect (custom submission method) ***
		if ( array_key_exists( 'thrive-leads/thrive-leads.php', $installed_plugins ) ) {
			$patterns[] = '{"thrive_leads_submit":null}';
			self::display_admin_notice( __( 'Thrive Leads detected – added recognition pattern: {"thrive_leads_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Thrive Apprentice (Online course signups) ***
		if ( array_key_exists( 'thrive-apprentice/thrive-apprentice.php', $installed_plugins ) ) {
			$patterns[] = '{"thrive_apprentice_signup":null}';
			self::display_admin_notice( __( 'Thrive Apprentice detected – added recognition pattern: {"thrive_apprentice_signup":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Thrive Quiz Builder (Quiz forms) ***
		if ( array_key_exists( 'thrive-quiz-builder/thrive-quiz-builder.php', $installed_plugins ) ) {
			$patterns[] = '{"thrive_quiz_submission":null}';
			self::display_admin_notice( __( 'Thrive Quiz Builder detected – added recognition pattern: {"thrive_quiz_submission":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Thrive Comments (replaces WordPress comments) ***
		if ( array_key_exists( 'thrive-comments/thrive-comments.php', $installed_plugins ) ) {
			$patterns[] = '{"comment_content":null,"comment_post_ID":null,"tva_term":null}';
			self::display_admin_notice( __( 'Thrive Comments detected – added recognition pattern: {"thrive_comments_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Formidable Forms (custom submission method) ***
		if ( array_key_exists( 'formidable/formidable.php', $installed_plugins ) ) {
			$patterns[] = '{"formidable_submit":null}';
			self::display_admin_notice( __( 'Formidable Forms detected – added recognition pattern: {"formidable_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WP User Frontend Forms (custom submission method) ***
		if ( array_key_exists( 'wp-user-frontend/wp-user-frontend.php', $installed_plugins ) ) {
			$patterns[] = '{"wpuf_submit":null}';
			self::display_admin_notice( __( 'WP User Frontend Forms detected – added recognition pattern: {"wpuf_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Jotform (custom submission method) ***
		if ( array_key_exists( 'jotform/jotform.php', $installed_plugins ) ) {
			$patterns[] = '{"jotform_submit":null}';
			self::display_admin_notice( __( 'Jotform detected – added recognition pattern: {"jotform_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Typeform (custom submission method) ***
		if ( array_key_exists( 'typeform/typeform.php', $installed_plugins ) ) {
			$patterns[] = '{"typeform_submit":null}';
			self::display_admin_notice( __( 'Typeform detected – added recognition pattern: {"typeform_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Zoho Forms (custom submission method) ***
		if ( array_key_exists( 'zoho-forms/zoho-forms.php', $installed_plugins ) ) {
			$patterns[] = '{"zoho_forms_submit":null}';
			self::display_admin_notice( __( 'Zoho Forms detected – added recognition pattern: {"zoho_forms_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return implode( "\n", $patterns );
	}

	public function prepare_options() {
		$pow_save_spam_label = sprintf(
			/* translators: %s: URL to the spam inbox page */
			__(
				"You can review your saved spam messages <a href='%s'>here</a>.",
				'gdpr-compliant-recaptcha-for-all-forms'
			),
			admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_SPAM
		);

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

		$this->options = array(
			Option::POW_DIRECT_ANALYSIS_MODE    => new Option(
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
			Option::POW_ANALYSIS_MODE           => new Option(
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
			Option::POW_EXPLICIT_ACTION         => new Option(
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
			Option::POW_PARAMETER_PATTERN       => new Option(
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
                    <br>Added patterns are listed here line by line, in JSON format, and can be edited directly.',
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS . '">',
					'</a>'
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔍✔️',
				__( 'Defines field/value patterns that identify a submission type so the spam check applies to it.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_BLOCK_LOGIN             => new Option(
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
			Option::POW_BLOCK                   => new Option(
				__( 'Block spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				$text_block . '<br><br><strong>Test first:</strong> ' . __( 'enable <em>Simulate spam messages</em> before switching this on for a live site — it lets you verify nothing legitimate gets blocked.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⛔', // Blocking
				__( 'Blocks submissions classified as spam instead of letting them through.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SPAM               => new Option(
				__( 'Flag spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				$text_flag,
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚩',
				__( 'Lets spam through but marks it so your mail client can filter it into a spam folder.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SUFFIXES           => new Option(
				__( 'Fieldname:prefix to flag spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				$text_flag_suffixes,
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'_*',
				__( 'Adds a text prefix such as [spam] to a chosen field when a message is flagged as spam.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_TAGS               => new Option(
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
			Option::POW_ERROR_MESSAGE           => new Option(
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
			Option::POW_SIMULATE_SPAM           => new Option(
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
			Option::POW_FAIL_2_BAN_PATH         => new Option(
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
			Option::POW_SAVE_CLEAN              => new Option(
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
			Option::POW_SAVE_SPAM               => new Option(
				__( 'Save spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				$pow_save_spam_label,
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'💾',
				__( 'Stores submissions classified as spam in the spam inbox so you can review them later.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_LOGIN              => new Option(
				__( 'Save Logins', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( "Disable this option if you don't want successful WordPress logins to be recorded.", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔒💾',
				__( 'Records successful WordPress logins in the message inbox.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SAVE               => new Option(
				__( 'Save spam messages with flag', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Controls whether spam messages are saved with their flag intact or with the flag stripped.<br><br>For testing whether flagging works as desired, it can be useful to save messages with their flags.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚩💾',
				__( 'Keeps the spam flag on messages that are saved, instead of stripping it before saving.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_IP                 => new Option(
				__( 'Save spam messages with IP', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__( "<strong>Warning:</strong> saving visitors' IP addresses does not comply with the European data privacy act <b>GDPR</b>.", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛡️💾',
				__( "Stores the submitter's IP address with saved spam messages (not GDPR-compliant).", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SKIP_FIELDS             => new Option(
				__( 'Skip fields from saving', 'gdpr-compliant-recaptcha-for-all-forms' ),
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
			Option::POW_MESSAGE_HEADS           => new Option(
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
			Option::POW_SAVE_CART               => new Option(
				__( 'Save WooCommerce shopping carts', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'If you get too many messages from shopping carts, you can disable this option.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛒',
				__( 'Saves WooCommerce shopping cart activity as messages in the inbox.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_INBOX       => new Option(
				__( 'Automatic Message Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️✉️',
				__( 'Automatically deletes messages from the inbox after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_SPAM        => new Option(
				__( 'Automatic Spam Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️📩',
				__( 'Automatically deletes messages from the spam inbox after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_TRASH       => new Option(
				__( 'Automatic Trash Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️📨',
				__( 'Automatically deletes messages from the trash after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_APPLY_REST              => new Option(
				__( 'Apply on REST-API', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__( 'This option improves site security a lot.<br><br><strong>Test first:</strong> enable <em>Simulate spam messages</em> before switching this on for a live site — it lets you verify nothing legitimate gets blocked.<br><br><strong>But beware</strong>: several plugins use the REST API for handshake procedures or vendor-side maintenance. In this case, control access for the specific plugin via the whitelisting options one by one.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🖥️',
				__( 'Applies the proof-of-work check to WordPress REST API requests as well as forms.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_IP_WHITELIST            => new Option(
				__( 'IP-Whitelist', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__( 'Add one IP per line, without any separator.<br><br><strong>Example:</strong><br>192.0.0.1<br>241.x.x.xxx<br>...', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🌐',
				__( 'Exempts the listed IP addresses from the spam check entirely.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SITE_WHITELIST          => new Option(
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
			Option::POW_TRUSTED_PROXIES         => new Option(
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
			Option::POW_HIDE_ACTION             => new Option(
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
			Option::POW_HIDE_PATTERN            => new Option(
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
			Option::POW_MENU_POSITION           => new Option(
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
			Option::POW_DASHBOARD               => new Option(
				__( 'Message counters on the Wordpress Dashboard', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Includes counts for messages, spam and trash (today and in total), so you can see activity at a glance without opening the inboxes.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'WordPress Administration', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📊', //Dashboard symbol
				__( 'Shows message counters as a widget on the WordPress dashboard.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SALT                    => new Option(
				__( 'Salt', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::STRING,
				hash( 'sha256', gmdate( 'Y-m-d H:i:s.u' ) ),
				__( "Set this to a random string to give some unknown salt to the puzzle. It increases security, as it can't be guessed client-side.<br><br>By default, this salt is generated as a hash from the point in time of your installation.", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔑',
				__( "Adds a secret random string to the proof-of-work puzzle so it can't be pre-computed client-side.", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_TIME_WINDOW             => new Option(
				__( 'Time Window', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				10,
				__( 'The number of minutes a hash-puzzle stays valid before it has to be computed and solved anew.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⌛',
				__( 'Sets how many minutes a generated hash-puzzle stays valid before it must be solved again.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_DIFFICULTY              => new Option(
				__( 'Difficulty', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				14,
				sprintf(
					/* translators: 1: under-attack difficulty bonus in bits (Stamp::UNDER_ATTACK_BONUS), 2: hard difficulty cap (Stamp::DIFFICULTY_CAP), 3: base difficulty at which the bonus starts getting clipped by the cap (cap minus bonus plus one) */
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
                        <br><strong>Recommended base: 15–16.</strong> Under-attack mode temporarily adds %1\$d bits on top of your base difficulty, but the effective difficulty is always capped at %2\$d — so once your base reaches %3\$d or higher, the boost gets clipped (partially, or at %2\$d entirely). A base of 15–16 keeps the full +%1\$d headroom available for the under-attack boost.
                        <br>
                        <br>The built-in solve-time plausibility gate (which re-challenges implausibly fast, likely non-browser solves) is effectively inactive below base ~16, where its threshold falls under normal network latency — another reason to keep the base at 15–16; from 16 upward it starts yielding a useful signal.",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					Stamp::UNDER_ATTACK_BONUS,
					Stamp::DIFFICULTY_CAP,
					Stamp::DIFFICULTY_CAP - Stamp::UNDER_ATTACK_BONUS + 1
				),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🧩',
				__( "Controls how much computing power a visitor's browser must spend solving the proof-of-work puzzle. Recommended base: 15–16, to leave headroom for the under-attack boost.", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_MAX_USES                => new Option(
				__( 'Max submissions per solved challenge', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				10,
				__( 'Bots that replay one solution are cut off after this many submissions; raise it if legitimate visitors submit many forms in quick succession.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔁',
				__( 'Caps how many form submissions a single solved proof-of-work may be used for within the validity window.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_UNDER_ATTACK_MODE       => new Option(
				__( 'Under-attack mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Based purely on a coarse, site-wide counter — no per-visitor data is collected or stored.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚨',
				__( 'Temporarily raises the puzzle difficulty for all visitors when site-wide spam suddenly spikes (+3 bits, roughly 8x the computing time, whenever 15+ blocked/flagged submissions occur within about 10 minutes).', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_UNDER_ATTACK_QUARANTINE => new Option(
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
			Option::POW_ECHO_LOCK_ENABLED       => new Option(
				__( 'Repeat-sender echo lock', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__(
					'<strong>What it does:</strong> Whenever a submission is classified as spam, the echo lock briefly remembers its core values (sender email, linked domain, phone number, and the hash of a long message body) as one-way hashes with a short lifetime. A later submission carrying the same value — on <em>any</em> form and from <em>any</em> IP — is then caught as well, so a returning spammer is stopped even after switching forms or rotating addresses.
					<br>
					<br><strong>Just a bonus layer:</strong> this only <em>adds</em> to the proof-of-work check; it never replaces it. Values are stored as hashes only (never in plain text) and expire on their own after about a day and a half.
					<br>
					<br><strong>Turn it off if</strong> (rarely) you would rather not carry values over between submissions at all — for example while diagnosing a false positive. Addresses of your registered users are already excluded automatically, so this is seldom necessary. You can also clear all currently held values at any time via <em>Reset repeat-sender lock</em> in the status bar at the top of this page.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔁',
				__( 'Briefly remembers the core values of spam submissions (as hashes) so the same sender/domain is caught again on any form. A bonus layer over the proof-of-work; on by default.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
		);

		//Check whether the installation was done already
		if ( ! get_option( Option::POW_INSTALLED ) ) {

			update_option( Option::POW_INSTALLED, true );

			foreach ( $this->options as $id => $option ) {

				update_option( $id, $option->get_default() );

			}
		}

		//Name the plugin
		$this->plugin_name = __( 'Invisible Anti-Spam', 'gdpr-compliant-recaptcha-for-all-forms' );

		$this->update_settings();
		$this->maybe_reset_echo_store();

		foreach ( $this->options as $id => $option ) {

			$type = $option->get_type();
			if ( Option::ROLE_DROPDOWN === $type ) {
				// Retrieve the raw option value as an array
				$raw_option_value = get_option( $id, array() );
				// Filter the array values as strings

				$filtered_value = array_map(
					function ( $value ) {
						return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' );
					},
					$raw_option_value
				);
				$option->set_value( $filtered_value );
			} else {
				// Fall back to the option-matrix default when no row exists in the DB
				// (options added after install are only seeded on upgrade, see
				// RCM_Main::activate()). Without the fallback a missing option renders
				// as off/empty although the runtime uses its code default — and saving
				// the page would persist that wrong displayed value.
				$raw_value = get_option( $id, $option->get_default() );
				if ( Option::INT === $type || Option::BOOL === $type ) {
					$option->set_value( intval( filter_var( $raw_value, $this->get_option_filter( $type ) ) ) );
				} else {
					// TEXT/STRING: keep the raw value — escaping happens at output
					// (esc_attr/esc_textarea in render_control()). The former
					// FILTER_SANITIZE_FULL_SPECIAL_CHARS here HTML-encoded quotes on
					// load, so e.g. JSON patterns displayed as {&quot;…&quot;} and the
					// encoded text got written back on the next save (value corruption).
					$option->set_value( strval( $raw_value ) );
				}
			}
		}

		$this->display_options();
	}

	/** Wenn the plugin is run
	 */
	public function run() {
		add_filter( sprintf( 'plugin_action_links_%s', plugin_basename( __FILE__ ) ), array( $this, 'get_action_links' ) );
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		add_action( 'admin_init', array( $this, 'prepare_options' ) );
		add_filter( 'plugin_action_links_' . GDPR_COMPLIANT_RECAPTCHA, array( $this, 'add_settings_link' ) );
	}

	/**  Get links for settings page
	 *
	 */
	public function get_action_links( $links ) {
		return array_merge( array( 'settings' => sprintf( '<a href="options-general.php%s">%s</a>', Option::PAGE_QUERY, __( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) ) ), $links );
	}

	/** Add the admin menu for the plugin
	 *
	 */
	public function admin_menu() {
		$page = add_submenu_page(
			'options-general.php',
			$this->plugin_name,
			__( 'ReCaptcha GDPR Compliant', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'manage_options',
			Option::PREFIX . 'options',
			array( $this, 'options_page' )
		);
		add_action( "admin_print_styles-{$page}", array( $this, 'enqueue_settings_page_ressources' ) );
	}

	// Add a "Settings" link to the plugin action links
	public function add_settings_link( $links ) {
		$url           = get_admin_url() . 'options-general.php?page=' . Option::PREFIX . 'options';
		$settings_link = '<a href="' . $url . '">' . __( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</a>';
		array_unshift( $links, $settings_link );
		return $links;
	}

	/**Add style only for settings page */
	public function enqueue_settings_page_ressources() {
		wp_enqueue_style( 'gdpr-settingsPageStyle' );
		wp_enqueue_script( 'gdpr-settingsPageScript' );
	}

	/** Registers styles/scripts for the settings page (no WP-Settings-API indirection
	 * anymore — options_page() renders the form directly, see there).
	 */
	public function display_options() {
		wp_register_style( 'gdpr-settingsPageStyle', plugins_url( '/css/style_admin.css', __DIR__ ), array(), RCM_Main::VERSION );
		wp_register_script( 'gdpr-settingsPageScript', plugins_url( '/scripts/recaptcha-gdpr-settings.js', __DIR__ ), array(), RCM_Main::VERSION, true );
	}

	/** Ordered list of distinct option groups (tab/panel order), derived from
	 * $this->options insertion order.
	 *
	 * @return string[]
	 */
	private function get_groups() {
		$groups = array();
		foreach ( $this->options as $option ) {
			$group = $option->get_group();
			if ( ! in_array( $group, $groups, true ) ) {
				$groups[] = $group;
			}
		}
		return $groups;
	}

	/** Badge map for option rows (design-layer only, not part of the options-matrix).
	 *
	 * @return array<string, array{class: string, text: string}>
	 */
	private function get_badge_map() {
		$warn = array(
			'class' => 'gdpr-badge gdpr-badge-warn',
			'text'  => __( 'Can lock out visitors', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
		return array(
			Option::POW_BLOCK       => $warn,
			Option::POW_APPLY_REST  => $warn,
			Option::POW_BLOCK_LOGIN => $warn,
			Option::POW_DIFFICULTY  => $this->get_difficulty_badge(),
		);
	}

	/** Dynamic badge for POW_DIFFICULTY: warns when the configured base difficulty
	 * leaves the under-attack boost (Stamp::UNDER_ATTACK_BONUS) partially or fully
	 * clipped by Stamp::DIFFICULTY_CAP, otherwise shows the recommendation. Evaluates
	 * the actually configured value (post-save), not a static hint.
	 *
	 * @return array{class: string, text: string}
	 */
	private function get_difficulty_badge() {
		$base_difficulty = (int) $this->options[ Option::POW_DIFFICULTY ]->get_value();

		if ( $base_difficulty + Stamp::UNDER_ATTACK_BONUS > Stamp::DIFFICULTY_CAP ) {
			return array(
				'class' => 'gdpr-badge gdpr-badge-warn',
				'text'  => sprintf(
					/* translators: 1: under-attack difficulty bonus in bits, 2: hard difficulty cap */
					__( 'Under-attack boost (+%1$d) is capped at %2$d — recommended base: 15–16', 'gdpr-compliant-recaptcha-for-all-forms' ),
					Stamp::UNDER_ATTACK_BONUS,
					Stamp::DIFFICULTY_CAP
				),
			);
		}

		return array(
			'class' => 'gdpr-badge gdpr-badge-recommend',
			'text'  => __( 'Recommended: 15–16', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
	}

	/** Allowlist shared by the header message and the per-option help popovers.
	 *
	 * @return array<string, array<string, array<int, string>>>
	 */
	private function get_allowed_html() {
		return array(
			'br'     => array(),
			'ol'     => array(),
			'ul'     => array(),
			'li'     => array(),
			'strong' => array(),
			'b'      => array(),
			'u'      => array(),
			'em'     => array(),
			'code'   => array(),
			'span'   => array( 'class' => array() ),
			'a'      => array(
				'href'  => array(),
				'title' => array(),
			),
		);
	}

	/** Renders the review/FAQ header line, escaped via wp_kses with a tight allowlist. */
	private function render_header_message() {
		$review_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( 'https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/reviews/#new-post' ),
			esc_html__( 'Help us and rate it', 'gdpr-compliant-recaptcha-for-all-forms' )
		);
		$faq_link    = sprintf(
			'<a href="%s">%s</a>',
			esc_url( 'https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/' ),
			esc_html__( 'Get help in the support forum', 'gdpr-compliant-recaptcha-for-all-forms' )
		);

		$message1 = sprintf(
			/* translators: 1: checkmark icon, 2,3: line breaks */
			__( '%1$s The plugin is now active on all of your forms and logins.%2$s%3$s', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'<span class="large-checkmark">&#10003;</span>',
			'<br>',
			'<br>'
		);
		$message2 = sprintf(
			/* translators: 1: smiley icon, 2: review link, 3,4: line breaks, 5: thinking-smiley icon, 6: FAQ link */
			__( '%1$s Happy with the plugin? %2$s %3$s%4$s %5$s Problems, questions, hints, improvements? %6$s', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'<span class="large-smiley">&#128578;</span>',
			$review_link,
			'<br>',
			'<br>',
			'<span class="large-smiley">&#129300;</span>',
			$faq_link
		);

		echo wp_kses( $message1 . $message2, $this->get_allowed_html() );
	}

	/** Status strip: protection/simulation state, effective difficulty, under-attack
	 * flag, weekly spam count (see SETTINGS_MODERNIZE_PLAN.md "Status-Leiste").
	 */
	private function render_status_strip() {
		$simulate        = get_option( Option::POW_SIMULATE_SPAM );
		$base_difficulty = (int) get_option( Option::POW_DIFFICULTY );
		// Same gate as Stamp::get_stamp(): the boost only applies while the
		// under-attack option is enabled (explicit `true` fallback, see there).
		$under_attack   = get_option( Option::POW_UNDER_ATTACK_MODE, true ) && Stamp::is_under_attack();
		$effective      = ProofOfWork::effective_difficulty( $base_difficulty, $under_attack, Stamp::UNDER_ATTACK_BONUS, Stamp::DIFFICULTY_CAP );
		$spam_this_week = Option::count_messages_since_days( 2, 7 );

		$items = array();

		if ( $simulate ) {
			$items[] = array(
				'class' => 'gdpr-status-amber',
				'text'  => __( 'Simulation mode active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		} else {
			$items[] = array(
				'class' => 'gdpr-status-green',
				'text'  => __( 'Protection active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		if ( $under_attack ) {
			$items[] = array(
				'class' => '',
				'text'  => sprintf(
					/* translators: 1: base difficulty, 2: applied under-attack bonus */
					__( 'Difficulty %1$d +%2$d (under attack)', 'gdpr-compliant-recaptcha-for-all-forms' ),
					$base_difficulty,
					$effective - $base_difficulty
				),
			);
			$items[] = array(
				'class' => 'gdpr-status-amber',
				'text'  => __( 'Under attack', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		} else {
			$items[] = array(
				'class' => '',
				/* translators: %d: configured difficulty */
				'text'  => sprintf( __( 'Difficulty %d', 'gdpr-compliant-recaptcha-for-all-forms' ), $base_difficulty ),
			);
		}

		// Quarantine is gated on the raw wave detection (Stamp::is_under_attack()),
		// independent of POW_UNDER_ATTACK_MODE (which only gates the difficulty boost
		// above) — so it can be actively sorting even when $under_attack is false here.
		// Surface a subtle hint only while it is actually acting (option on + wave +
		// not simulating, mirroring the check_submit() gate).
		if ( ! $simulate && get_option( Option::POW_UNDER_ATTACK_QUARANTINE ) && Stamp::is_under_attack() ) {
			$items[] = array(
				'class' => '',
				'text'  => __( 'Quarantine active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		$items[] = array(
			'class' => '',
			/* translators: %d: number of spam messages blocked in the last 7 days */
			'text'  => sprintf( __( '%d spam blocked this week', 'gdpr-compliant-recaptcha-for-all-forms' ), $spam_this_week ),
		);

		// Health counter: submissions whose classification reason was "no usable stamp
		// row" (no_pow:*) in the last 24h — the fingerprint of a broken client-PoW
		// pipeline (HANDBUCH §12). Amber above the threshold; the decision itself is the
		// pure Option::health_counter_status().
		$no_pow_count  = Option::count_no_pow_reasons_since_hours( Option::HEALTH_NO_POW_WINDOW_HOURS );
		$no_pow_status = Option::health_counter_status( $no_pow_count, Option::HEALTH_NO_POW_WARN_THRESHOLD );
		$items[]       = array(
			'class' => $no_pow_status['class'],
			'text'  => sprintf(
				/* translators: %d: number of submissions in the last 24 hours that had no usable proof-of-work stamp */
				_n( '%d submission without a stamp row (24h)', '%d submissions without a stamp row (24h)', $no_pow_count, 'gdpr-compliant-recaptcha-for-all-forms' ),
				$no_pow_count
			),
		);

		// Repeat-sender echo lock: how many values it currently holds, plus a one-click
		// reset (offered only when non-empty). The count reflects the store even when
		// the feature is toggled off, so a stale value can still be released.
		$echo_count = Echo_Store::count();
		$items[]    = array(
			'class' => '',
			'text'  => sprintf(
				/* translators: %d: number of values currently held in the repeat-sender echo lock */
				_n( '%d value in repeat-sender lock', '%d values in repeat-sender lock', $echo_count, 'gdpr-compliant-recaptcha-for-all-forms' ),
				$echo_count
			),
		);
		?>
		<div class="gdpr-status-strip">
			<?php foreach ( $items as $item ) : ?>
				<span class="gdpr-status-item <?php echo esc_attr( $item['class'] ); ?>"><?php echo esc_html( $item['text'] ); ?></span>
			<?php endforeach; ?>
		</div>
		<?php if ( $echo_count > 0 ) : ?>
			<form method="post" action="<?php echo esc_attr( Option::PAGE_QUERY ); ?>" class="gdpr-echo-reset">
				<?php wp_nonce_field( 'gdpr_reset_echo_nonce', 'gdpr_reset_echo_nonce_field' ); ?>
				<input type="hidden" name="<?php echo esc_attr( self::RCM_ACTION ); ?>" value="<?php echo esc_attr( self::RESET_ECHO ); ?>">
				<button type="submit" class="button button-secondary"><?php esc_html_e( 'Reset repeat-sender lock', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></button>
				<span class="gdpr-echo-reset-hint">
					<?php esc_html_e( 'The repeat-sender lock briefly remembers values from spam submissions (as one-way hashes) so the same sender is caught again on any form. Resetting releases every currently held value at once — use it if a legitimate address got caught. No data is lost, and the lock rebuilds itself as new spam arrives.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
				</span>
			</form>
		<?php endif; ?>
		<?php
	}

	/** Renders one option row: label, optional badge, optional short description,
	 * control, help toggle + popover.
	 *
	 * @param string $key
	 * @param Option $option
	 */
	private function render_option_row( $key, Option $option ) {
		$badge_map = $this->get_badge_map();
		$short     = $option->get_short();
		?>
		<div class="gdpr-option-row">
			<div class="gdpr-option-main">
				<label class="gdpr-option-label" for="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $option->get_name() ); ?></label>
				<?php if ( isset( $badge_map[ $key ] ) ) : ?>
					<span class="<?php echo esc_attr( $badge_map[ $key ]['class'] ); ?>"><?php echo esc_html( $badge_map[ $key ]['text'] ); ?></span>
				<?php endif; ?>
				<?php if ( '' !== $short ) : ?>
					<p class="gdpr-option-short"><?php echo esc_html( $short ); ?></p>
				<?php endif; ?>
			</div>
			<div class="gdpr-option-control">
				<?php $this->render_control( $key, $option ); ?>
				<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_<?php echo esc_attr( $key ); ?>">?</button>
				<div class="gdpr-help-popover" id="help_<?php echo esc_attr( $key ); ?>" hidden>
					<?php echo wp_kses( $option->get_hint(), $this->get_allowed_html() ); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/** Renders the input control for one option, by type.
	 *
	 * @param string $key
	 * @param Option $option
	 */
	private function render_control( $key, Option $option ) {
		$type = $option->get_type();
		$val  = $option->get_value();

		if ( Option::BOOL === $type ) {
			?>
			<label class="gdpr-toggle">
				<input type="checkbox" name="<?php echo esc_attr( $key ); ?>" id="<?php echo esc_attr( $key ); ?>" <?php checked( (bool) $val ); ?> />
				<span class="gdpr-toggle-slider"></span>
			</label>
			<?php
		} elseif ( Option::INT === $type ) {
			?>
			<input type="number" name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $val ); ?>" />
			<?php
		} elseif ( Option::STRING === $type ) {
			?>
			<input type="text" name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $val ); ?>" />
			<?php
		} elseif ( Option::TEXT === $type ) {
			?>
			<textarea name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>"><?php echo esc_textarea( $val ); ?></textarea>
			<?php
		} elseif ( Option::ROLE_DROPDOWN === $type ) {
			// ROLE_DROPDOWN branch kept functional though unused by the current
			// options-matrix (see SETTINGS_MODERNIZE_PLAN.md).
			$selected_roles = (array) $val;
			$all_roles      = get_editable_roles();
			?>
			<select name="<?php echo esc_attr( $key ); ?>[]" id="<?php echo esc_attr( $key ); ?>" multiple="multiple">
				<?php foreach ( $all_roles as $role_key => $role ) : ?>
					<option value="<?php echo esc_attr( $role_key ); ?>" <?php selected( in_array( $role_key, $selected_roles, true ) ); ?>>
						<?php echo esc_html( $role['name'] ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<?php
		}
	}

	/** Updating the values for the options
	 *
	 */
	public function update_settings() {
		$post_action = strval( filter_input( INPUT_POST, self::RCM_ACTION, FILTER_SANITIZE_SPECIAL_CHARS ) );
		// If update and current user is allowed to manage options
		if ( self::UPDATE === $post_action && current_user_can( 'manage_options' ) ) {
			$hash  = null;
			$nonce = isset( $_POST['gdpr_settings_nonce_field'] ) ? sanitize_text_field( wp_unslash( $_POST['gdpr_settings_nonce_field'] ) ) : '';
			if ( '' === $nonce || ! wp_verify_nonce( $nonce, 'gdpr_settings_nonce' ) ) {
				wp_die( esc_html__( 'Security check failed. This request was blocked by an active CSRF protection mechanism. It may have been triggered by another webpage you recently visited or an unrelated browser tab. To resolve this issue, close untrusted sites, check browser extensions, and refresh your WordPress session by logging in again.', 'gdpr-compliant-recaptcha-for-all-forms' ) );
			}

			foreach ( $this->options as $key => $option ) {
				$type = $option->get_type();
				// Check if the input is an array or a single value
				$is_array = Option::ROLE_DROPDOWN === $type;

				if ( $is_array ) {
					// For arrays, filter as strings
					$post_value = filter_input( INPUT_POST, $key, FILTER_DEFAULT, FILTER_REQUIRE_ARRAY );
					$post_value ? array_map( 'sanitize_text_field', $post_value ) : array();
				} elseif ( Option::TEXT === $type || Option::STRING === $type ) {
					$post_value = isset( $_POST[ $key ] ) ? wp_kses_post( wp_unslash( $_POST[ $key ] ) ) : null;
				} else {
					// For single values, apply the specified filter
					$post_value = filter_input( INPUT_POST, $key, $this->get_option_filter( $type ) );
				}

				// The fail2ban log path is a filesystem location the plugin writes to. On
				// multisite a plain site admin (manage_options) must not be able to aim it
				// at an arbitrary path — restrict that to super admins — and reject path
				// traversal on any install. An invalid value is left unchanged (the old
				// path stays), never silently redirected.
				if ( Option::POW_FAIL_2_BAN_PATH === $key && ! empty( $post_value )
					&& ( ( is_multisite() && ! is_super_admin() ) || 0 !== validate_file( (string) $post_value ) ) ) {
					continue;
				}

				if ( Option::BOOL === $type && ( null === $post_value || false === $post_value ) ) {
					// Checkbox unchecked: persist an explicit '0' instead of
					// delete_option(). Bestand: delete_option() + the options-matrix
					// default-fallback in prepare_options() made an unchecked
					// default-true option show as "on" again after saving, while the
					// runtime already read it as "off" via get_option() (no fallback
					// there) — a visible/actual state mismatch.
					update_option( $key, '0' );
				} elseif ( null !== $post_value && ( $is_array || false !== $post_value ) ) {
					update_option( $key, $post_value );

					if ( $is_array ) {
						$hash .= implode( '', $post_value );
					} elseif ( '_key' === substr( $key, -strlen( '_key' ) ) ) {
						$hash .= $post_value;
					}
				} else {
					delete_option( $key );
				}
			}
			// Add success message
			add_settings_error(
				Option::PREFIX . 'options',
				'my-plugin-success',
				__( 'Success! Your settings have been saved.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'updated'
			);
		}
	}

	/** Handle the "reset repeat-sender echo lock" status-strip button.
	 *
	 * Native admin-post-style flow: the button submits a normal form to the settings
	 * page carrying self::RESET_ECHO plus its own CSRF nonce. Runs on admin_init (via
	 * prepare_options()) BEFORE the page renders, so the status strip already shows the
	 * emptied store. Gated by both a valid nonce and the manage_options capability.
	 *
	 * @return void
	 */
	public function maybe_reset_echo_store() {
		$post_action = strval( filter_input( INPUT_POST, self::RCM_ACTION, FILTER_SANITIZE_SPECIAL_CHARS ) );
		if ( self::RESET_ECHO !== $post_action || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$nonce = isset( $_POST['gdpr_reset_echo_nonce_field'] ) ? sanitize_text_field( wp_unslash( $_POST['gdpr_reset_echo_nonce_field'] ) ) : '';
		if ( '' === $nonce || ! wp_verify_nonce( $nonce, 'gdpr_reset_echo_nonce' ) ) {
			wp_die( esc_html__( 'Security check failed. This request was blocked by an active CSRF protection mechanism. It may have been triggered by another webpage you recently visited or an unrelated browser tab. To resolve this issue, close untrusted sites, check browser extensions, and refresh your WordPress session by logging in again.', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}
		Echo_Store::clear();
		add_settings_error(
			Option::PREFIX . 'options',
			'gdpr-echo-reset',
			__( 'The repeat-sender lock has been reset — all currently held values were released.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'updated'
		);
	}

	/** Filter special chars if not int
	 *
	 */
	private function get_option_filter( $type ) {
		$filter = '';
		if ( Option::INT === $type ) {
			$filter = FILTER_SANITIZE_NUMBER_INT;
		} elseif ( Option::BOOL === $type ) {
			$filter = FILTER_VALIDATE_BOOLEAN;
		} else {
			$filter = FILTER_SANITIZE_FULL_SPECIAL_CHARS;
		}
		return $filter;
	}

	/**
	 * Drawing the options page for the plugin: status strip, pill tabs and one
	 * card per group, all rendered directly (no WP-Settings-API indirection).
	 */
	public function options_page() {
		$groups  = $this->get_groups();
		$tab_ids = array();
		foreach ( $groups as $group ) {
			$tab_ids[] = 'gdpr-tab-' . sanitize_title( $group );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only: only re-selects the active pill tab for display (sanitize_key()'d, no state change); the actual save path in update_settings() already verifies gdpr_settings_nonce before writing anything.
		$requested_tab = isset( $_POST['gdpr-settings-selection'] ) ? sanitize_key( wp_unslash( $_POST['gdpr-settings-selection'] ) ) : '';
		$active_tab    = in_array( $requested_tab, $tab_ids, true ) ? $requested_tab : ( isset( $tab_ids[0] ) ? $tab_ids[0] : '' );
		?>
		<div class="wrap gdpr-settings-wrap">
			<h1><?php echo esc_html( $this->plugin_name . ' - ' . __( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) ); ?></h1>
			<?php $this->render_header_message(); ?>
			<?php $this->render_status_strip(); ?>
			<nav class="gdpr-pill-tabs">
				<?php foreach ( $groups as $group ) : ?>
					<?php
					$tab_id    = 'gdpr-tab-' . sanitize_title( $group );
					$is_active = ( $tab_id === $active_tab );
					?>
					<button type="button" class="gdpr-pill-tab<?php echo $is_active ? ' is-active' : ''; ?>" data-tab-target="<?php echo esc_attr( $tab_id ); ?>"><?php echo esc_html( $group ); ?></button>
				<?php endforeach; ?>
			</nav>
			<form class="gdpr-settings-form" method="post" action="<?php echo esc_attr( Option::PAGE_QUERY ); ?>">
				<?php wp_nonce_field( 'gdpr_settings_nonce', 'gdpr_settings_nonce_field' ); // CSRF-protection add ?>
				<input type="hidden" name="<?php echo esc_attr( self::RCM_ACTION ); ?>" value="<?php echo esc_attr( self::UPDATE ); ?>">
				<input type="hidden" id="gdpr-settings-selection" name="gdpr-settings-selection" value="<?php echo esc_attr( $active_tab ); ?>">
				<?php foreach ( $groups as $group ) : ?>
					<?php
					$tab_id    = 'gdpr-tab-' . sanitize_title( $group );
					$is_active = ( $tab_id === $active_tab );
					?>
					<section class="gdpr-tab-panel" id="<?php echo esc_attr( $tab_id ); ?>"<?php echo $is_active ? '' : ' hidden'; ?>>
						<div class="gdpr-card">
							<?php
							foreach ( $this->options as $key => $option ) {
								if ( $option->get_group() === $group ) {
									$this->render_option_row( $key, $option );
								}
							}
							?>
						</div>
					</section>
				<?php endforeach; ?>
				<div id="submit-container">
					<?php submit_button(); ?>
				</div>
			</form>
		</div>
		<?php
	}
}