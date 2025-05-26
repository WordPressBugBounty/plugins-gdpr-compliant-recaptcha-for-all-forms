<?php 

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) or die( 'Are you ok?' );
/**
 * Class Message_Page: Reflects the module for the administration of messages
 */

class Settings_Menu
{

    /** Holding the instance of this class */
    public static $instance;

    /** String that represents the name of the plugin */
    private $plugin_name;

    /** Feld der Optionen */
    private $options;

    /** Option based action */
    const RCM_ACTION = Option::PREFIX . 'action';

    /** What to do with the action */
    const UPDATE = 'update';

    /** Get an instance of the class
     * 
     */
    public static function getInstance()
    {
        require_once dirname( __FILE__ ) . '/class-option.php';

        if ( ! self::$instance instanceof self ) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /** Constructor of the class
     */
    public function __construct()
    {
        add_action( 'init', [ $this, 'run' ] );
    }

    /**
     * Display an admin notice in the backend.
     *
     * @param string $message The message to be displayed.
     */
    function display_admin_notice( $message ) {
        if ( ! is_admin() || get_option( Option::POW_INSTALLED ) ) {
            return;
        }
        add_action( 'admin_notices', function() use ( $message ) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $message ) . '</p></div>';
        } );
    }

    function get_default_ajax_actions() {
        include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
        $actions = [];
        $installed_plugins = get_plugins();
        $installed_themes  = wp_get_themes();
    
        // *** Thrive Architect Forms (custom submission method) ***
        if ( array_key_exists( 'thrive-architect/thrive-architect.php', $installed_plugins ) ) {
            $actions[] = 'tve_api_form_submit';
            $this->display_admin_notice( __( 'Thrive Architect detected – added recognition pattern: {"thrive_architect_form_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }

        // *** Forminator (uses WordPress AJAX) ***
        if ( is_plugin_active( 'forminator/forminator.php' ) || array_key_exists( 'forminator/forminator.php', $installed_plugins ) ) {
            $actions[] = 'forminator_submit_form_custom-forms';
            $this->display_admin_notice( __( 'Forminator detected – added action: forminator_submit_form_custom-forms', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** WPForms (uses WordPress AJAX) ***
        if ( array_key_exists( 'wpforms/wpforms.php', $installed_plugins ) || array_key_exists( 'wpforms-lite/wpforms.php', $installed_plugins ) ) {
            $actions[] = 'wpforms_submit';
            $this->display_admin_notice( __( 'WPForms detected – added action: wpforms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Ninja Forms (uses WordPress AJAX) ***
        if ( array_key_exists( 'ninja-forms/ninja-forms.php', $installed_plugins ) ) {
            $actions[] = 'nf_ajax_submit';
            $this->display_admin_notice( __( 'Ninja Forms detected – added action: nf_ajax_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Fluent Forms (uses WordPress AJAX) ***
        if ( array_key_exists( 'fluentform/fluentform.php', $installed_plugins ) ) {
            $actions[] = 'fluentform_submit';
            $this->display_admin_notice( __( 'Fluent Forms detected – added action: fluentform_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Jetpack Forms (uses WordPress AJAX) ***
        if ( array_key_exists( 'jetpack/jetpack.php', $installed_plugins ) ) {
            $actions[] = 'jetpack_contact_form_submit';
            $this->display_admin_notice( __( 'Jetpack Forms detected – added action: jetpack_contact_form_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Everest Forms (uses WordPress AJAX) ***
        if ( array_key_exists( 'everest-forms/everest-forms.php', $installed_plugins ) ) {
            $actions[] = 'everest_forms_submit';
            $this->display_admin_notice( __( 'Everest Forms detected – added action: everest_forms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** WS Forms (uses WordPress AJAX) ***
        if ( array_key_exists( 'ws-forms/ws-forms.php', $installed_plugins ) ) {
            $actions[] = 'ws_forms_submit';
            $this->display_admin_notice( __( 'WS Forms detected – added action: ws_forms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Otter Blocks (uses WordPress AJAX) ***
        if ( array_key_exists( 'otter-blocks/otter-blocks.php', $installed_plugins ) ) {
            $actions[] = 'otter_blocks_submit';
            $this->display_admin_notice( __( 'Otter Blocks detected – added action: otter_blocks_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Elementor Pro Forms (correct action) ***
        if ( array_key_exists( 'elementor-pro/elementor-pro.php', $installed_plugins ) ) {
            $actions[] = 'elementor_pro_forms_send_form';
            $this->display_admin_notice( __( 'Elementor Pro Forms detected – added action: elementor_pro_forms_send_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
        
        return implode("\n", $actions);
    }

    function get_default_recognition_patterns() {
        include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
        $patterns = [];
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
            $this->display_admin_notice( __( 'Contact Form 7 detected – added default recognition patterns', 'gdpr-compliant-recaptcha-for-all-forms' ) );
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
            $this->display_admin_notice( __( 'WooCommerce detected – added recognition patterns for cart, checkout, and user actions', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Gravity Forms (custom submission method) ***
        if ( array_key_exists( 'gravityforms/gravityforms.php', $installed_plugins ) ) {
            $patterns[] = '{"gform_submit":null}';
            $patterns[] = '{"gform_file_upload":null}';
            $this->display_admin_notice( __( 'Gravity Forms detected – added recognition patterns for submissions and file uploads', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Divi Contact Form Module (custom submission method) ***
        if ( array_key_exists( 'Divi', $installed_themes ) ) {
            $patterns[] = '{"et_pb_contactform_submit_0":null}';
            $this->display_admin_notice( __( 'Divi detected – added recognition pattern: {"et_pb_contactform_submit_0":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Thrive Leads & Thrive Architect (custom submission method) ***
        if ( array_key_exists( 'thrive-leads/thrive-leads.php', $installed_plugins ) ) {
            $patterns[] = '{"thrive_leads_submit":null}';
            $this->display_admin_notice( __( 'Thrive Leads detected – added recognition pattern: {"thrive_leads_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Thrive Apprentice (Online course signups) ***
        if ( array_key_exists( 'thrive-apprentice/thrive-apprentice.php', $installed_plugins ) ) {
            $patterns[] = '{"thrive_apprentice_signup":null}';
            $this->display_admin_notice( __( 'Thrive Apprentice detected – added recognition pattern: {"thrive_apprentice_signup":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Thrive Quiz Builder (Quiz forms) ***
        if ( array_key_exists( 'thrive-quiz-builder/thrive-quiz-builder.php', $installed_plugins ) ) {
            $patterns[] = '{"thrive_quiz_submission":null}';
            $this->display_admin_notice( __( 'Thrive Quiz Builder detected – added recognition pattern: {"thrive_quiz_submission":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Thrive Comments (replaces WordPress comments) ***
        if ( array_key_exists( 'thrive-comments/thrive-comments.php', $installed_plugins ) ) {
            $patterns[] = '{"comment_content":null,"comment_post_ID":null,"tva_term":null}';
            $this->display_admin_notice( __( 'Thrive Comments detected – added recognition pattern: {"thrive_comments_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Formidable Forms (custom submission method) ***
        if ( array_key_exists( 'formidable/formidable.php', $installed_plugins ) ) {
            $patterns[] = '{"formidable_submit":null}';
            $this->display_admin_notice( __( 'Formidable Forms detected – added recognition pattern: {"formidable_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** WP User Frontend Forms (custom submission method) ***
        if ( array_key_exists( 'wp-user-frontend/wp-user-frontend.php', $installed_plugins ) ) {
            $patterns[] = '{"wpuf_submit":null}';
            $this->display_admin_notice( __( 'WP User Frontend Forms detected – added recognition pattern: {"wpuf_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Jotform (custom submission method) ***
        if ( array_key_exists( 'jotform/jotform.php', $installed_plugins ) ) {
            $patterns[] = '{"jotform_submit":null}';
            $this->display_admin_notice( __( 'Jotform detected – added recognition pattern: {"jotform_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Typeform (custom submission method) ***
        if ( array_key_exists( 'typeform/typeform.php', $installed_plugins ) ) {
            $patterns[] = '{"typeform_submit":null}';
            $this->display_admin_notice( __( 'Typeform detected – added recognition pattern: {"typeform_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
    
        // *** Zoho Forms (custom submission method) ***
        if ( array_key_exists( 'zoho-forms/zoho-forms.php', $installed_plugins ) ) {
            $patterns[] = '{"zoho_forms_submit":null}';
            $this->display_admin_notice( __( 'Zoho Forms detected – added recognition pattern: {"zoho_forms_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
        }
            
        return implode("\n", $patterns);
    }

    public function prepare_options(){
        //$boolOptionType = Option::BOOL;
        $POW_SAVE_SPAM_LABEL = sprintf( __( "If you want to check that only spam messages are blocked. You can see your saved spam messages <a href='%s'>here</a>", 'gdpr-compliant-recaptcha-for-all-forms' ), admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_SPAM );

        $text_block = __( trim( <<<EOT
            If you want to block spam.
            EOT ), 'gdpr-compliant-recaptcha-for-all-forms' );

        $text_flag = __( trim( <<<EOT
            <strong>The purpose:</strong> This option might be useful, if your message shall be routed to your mail-adress and you still want to get all mails,
            <br>but spam messages shall be flagged respectively and you want to use your mail programm to order the flagged mails into your spam folder
            <br>
            <br>If you want to flag spam messages in a specific field or by creating a new field instead of blocking them, you should
            <br>
            <br><ul>
                    <li>disable <b>Block spam</b> ⛔</li>
                    <li>and either maintain the option <b>Fieldname:prefix to flag spam _*</b>, if you wish to signal spam via an existing technical field </li>
                    <li>or maintain the option <b>New "POST" field to flag spam +</b>, if you wish to signal spam via a complete new technical field</li>
                </ul>
            EOT ), 'gdpr-compliant-recaptcha-for-all-forms' );

        $text_flag_suffixes = sprintf( __( trim( <<<EOT
            <strong>The purpose:</strong> With this option you can specify how spam shall be flagged. The flagging works by adding a prefix (i.e. "[spam]") to the value of a certain field (i.e. a subject field) from a specific source of submission (i.e. your contact form).
            <br>In your email-client you can use this prefix to create a rule for shifting spam mails into the spam folder.
            <br>
            <br><strong>For example</strong> 
            <br><ul>
                    <li>the subject <em>"New contact request"</em>,</li>
                    <li>that is submitted with the field <em>"subject"</em> of the contact form,</li>
                    <li>can be changed to <em>"[spam]New contact request"</em></li>
                    <li>if the submission is classified as spam.</li>
                </ul>
            <br><strong>How it works:</strong> In order to flag spam via prefix, enter the combination of fieldname and prefix into this textbox.
            <br>The fieldname has to be the specific technical fieldname of the message which you want to flag
            <br>If you don't know the exact technical fieldnames of the respective form, you can get them this way:
                <br><ol>
                    <li>Tick the box for 'Save clean messages'</li>
                    <li>Post a message from the respective form</li>
                    <li>Open the %sMessage inbox%s and the just received message respectively</li>
                    <li>Look for the field you want to use for flagging and take the name of the respective attribute without apostrophs</li>
                    <li>If you fieldname is nested, it may look a bit confusing (example: 'wpforms->fields->0->first' ). This is the case when your form builder is using a nested field structure. In this case the fieldname represents the field structure respectively. Nevertheless just copy the whole field name without the colon at the end.</li>
                </ol>
            <br><strong>The format: </strong><em>fieldname:prefix</em>
            <br>
            <br><strong>Examples:</strong>
            <br><em>prename:spam</em>
            <br><em>wpforms->fields->0->first:[spam]</em>
            <br>
            <br><strong>Multiple fields: </strong>If you want to add different flaggs to different technical fields, you can do so by entering a new line for each combination of technical fieldname and prefix.
            <br>This may be helpful in order to cope with different sources for submissions, which usually come along with different technical fieldnames
            EOT ), 'gdpr-compliant-recaptcha-for-all-forms' ), '<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES .'">', '</a>' );

        $this->options = [
            Option::POW_DIRECT_ANALYSIS_MODE => new Option(
                __( 'Direct analysis mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                false,
                sprintf( __( trim( "
                    <strong>How it works:</strong><br>
                    Once activated...<br>
                    <ol>
                        <li>Navigate to the pages containing your forms.</li>
                        <li>Submit the forms you want to add to the spam check.</li>
                        <li>Enhance the spam check directly from your pages.</li>
                        <li>Follow additional instructions provided on the forms.</li>
                        <li>Finally, remember to deactivate the mode.</li>
                    </ol>
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ), admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS ),
                __( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🕵️'
            ),
            Option::POW_ANALYSIS_MODE => new Option(
                __( 'Analysis mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                false,
                sprintf( __( trim( "
                    <strong>The purpose:</strong> If you cannot see specific submissions in the messages or in the spam inbox, you can enable the analysis mode. As many types of POST-submissions belong to technical background processes, they are ignored by the spam check. Therefore the spam check is running only for the standard submission-routine of WordPress.
                    But many form builders and other plugins that allow visitors to post content, are using proprietary ways for these submissions.
                    <br>
                    <br><strong>How it works:</strong> In this mode all types of POST-submissions will be saved into the <a href='%s'>Analytic Box</a> which is a further type of inbox of this plugin and that can be used to enhance the scope of the spam check.
                    <br><br>
                    <ol>
                        <li>Submit the specific form type that you want to be considered by the spam check</li>
                        <li>Visit the inbox <a href='%s'>Analytic Box</a> and look for the corresponding message related to your submission (usually, it's one of the latest submissions)</li>
                        <li>If the message is of type Non-Ajax-Request you need to choose the patterns from the fields and the values of the message. If a message has all the attributes and values that you choose now, in the future it will be considered by the spam check. You should try to select as few pattern elements as possible. Example: In order to consider contact form 7, you should use \"_wpcf7\", as all submissions from contact form 7 use this key and unlikely other submission types will use the same. </li>
                        <li>Enhance the spam check by clicking the relevant button at the bottom of the message to specify the type of submission or action</li>
                        <li>In some cases, a form submission might trigger multiple separate requests, each resulting in a different message in the Analytic Box. Consider all of them, if applicable</li>
                        <li>Disable <b>Analysis mode</b> 🔍 to stop recording</li>
                    </ol>
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ), admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS, admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS ),
                __( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🔍'
            ),
            Option::POW_EXPLICIT_ACTION => new Option(
                __( 'Apply on actions', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                $this->get_default_ajax_actions(),
                sprintf( __( trim( "
                        Add line by line actions, that you wish to be considered from the spam protection, if the plugin is in the <b>Explicit mode</b> 🎯. 
                        <br>You can find and copy the action from unwanted messages in the plugin's %sspam or message inbox%s. Or you can use the <b>Analysis mode</b> 🔍 in order to record all types of submissions, open the <a href='%s'>Analytic Box</a>, search for the related message and add its action by clicking the respective button on the bottom of this message.
                        <br>
                        <br><strong>Example:</strong> 
                        <br>
                        <br><em>forminator_submit_form_custom-forms</em>
                        <br><em>wpforms_submit</em>
                    " ), 'gdpr-compliant-recaptcha-for-all-forms' ) , '<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES .'">', '</a>', admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS ),
                __( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '⚙️✔️'
            ),
            Option::POW_PARAMETER_PATTERN => new Option(
                __( 'Apply on pattern', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                $this->get_default_recognition_patterns(),
                sprintf( __( trim( "
                    <strong>The purpose:</strong> This option is intended to specify patterns for post parameters to enhance the scope for the spam check. 
                    If you are facing the problem, that your form submissions are not filtered by the spam check, the most likely reason is that the submission type of the respective forms are not yet recognized by the spam check.
                    <br>
                    <br><strong>How it works:</strong> Whereas at this point you can insert and view parameter patterns, the best and easiest way to insert new patterns is to enable <b>Analysis mode</b> 🔍, then submit the form that you want to be considered and search into the %sAnalytic Box%s for the message related to your submission.
                    Open the message, choose the fields and values for your pattern and add the pattern by clicking on the respective button on the bottom of the message.
                    <br>Finally you can view and alter all added patterns line by line at this option. The patterns use json format.
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ) , '<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS .'">', '</a>' ),
                __( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🔍✔️'
            ),
            Option::POW_BLOCK_LOGIN => new Option(
                __( 'Apply for WordPress-Login', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                true,
                __( trim( "This option improves the site-security a lot.
                    <br><br><strong>But beware</strong>: For every plugin that is securing the WP login I recommend to use this only,
                    <br>if you know how to switch it off without login. (i.e. by deleting the plugin files from your plugin directory)
                    <br>Because, if anything goes wrong the plugin will block your login" ), 'gdpr-compliant-recaptcha-for-all-forms' ),
                    __( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🔒'
            ),
            Option::POW_BLOCK => new Option(
                __( 'Block spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                true,
                $text_block,
                __( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '⛔' // Blocking
            ),
            Option::POW_FLAG_SPAM => new Option(
                __( 'Flag spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                false,
                $text_flag,
                __( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🚩'
            ),
            Option::POW_FLAG_SUFFIXES => new Option(
                __( 'Fieldname:prefix to flag spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                $text_flag_suffixes,
                __( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '_*'
            ),
            Option::POW_FLAG_TAGS => new Option(
                __( 'New "POST" field to flag spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                __( trim( "<strong>The purpose:</strong> This option is usefull if you want to flag spam via specific new post-fields. These fields can be used during further processing (i.e. a mailer, some routines to store messages in your database, a mail client, ...)
                <br>
                <br><strong>Beware: </strong> This option overrides existing post-fields with the same name, which may affect further processing. If you want to be sure, that you do not override existing fields. Check the technical field names of your messages, like described for the prefixes
                <br>
                <br><strong>How it works:</strong>
                <br>If you have different follow-up processings, which require for different specific fields to flag spam, you can add multiple fields. 
                <br>For each combination of <em>field:value</em> add a new line
                <br>
                <br><strong>Example:</strong> <em>spam_filter:spam</em>
                <br>
                <br>Applying this rule a flagged spam message with the following post-attributes ...
                <br>
                <br><em>{'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', 'message':'Hi there'}</em>
                <br>
                <br>... would now turn into ...
                <br>
                <br><em>{'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', 'message':'Hi there', 'spam_filter':'spam'}<br></em>" ),
                'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '+'
            ),
            Option::POW_ERROR_MESSAGE => new Option(
                __( 'Error message', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::STRING,
                __( 'Your message has been classified as spam! If you are a human, we are very sorry. Please give us notice via email.', 'gdpr-compliant-recaptcha-for-all-forms' ),
                __("
                    Here you can define an error message, that is shown to the frontend if a message has been identified as spam.
                    <br>
                    <br>Usually users will never see these messages, but if anything goes wrong, you have the chance to give some meaningfull advice.
                    <br>
                    <br>For some form builders, or other relevant plugins the error message won't pop up. This due to the fact that each plugin is using its own formats.
                ", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '❌'
            ),
            Option::POW_SIMULATE_SPAM => new Option(
                __( 'Simulate spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                false,
                __("If checked, each incoming submission is treated as spam. This option can be used in order to test whether the flagging of a spam message works as desired. It is not aplied on Wordpress login.<br><br><strong>***Beware:</strong> Do not forget to uncheck this option, as soon as your testing is done",
                'gdpr-compliant-recaptcha-for-all-forms'
                ),
                __( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '📈'
            ),
            Option::POW_FAIL_2_BAN_PATH => new Option(
                __( 'Path to save spam approaches to syslog', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                __( trim( "<strong>The purpose:</strong> <br>Fail2Ban is a security tool designed to <strong>protect servers</strong> by monitoring log files and automatically blocking IP addresses involved in <strong>repeated unauthorized access attempts or suspicious activities</strong>.
                            <br>While commonly used for <strong>SSH, email servers, and web applications</strong>, this integration focuses on securing WordPress forms from login abuse and spam.<br>

                            <br><strong>Specify the directory path where log files should be stored:</strong>
                            <ol>
                            <li>If the field is <strong>left empty or contains an invalid path</strong>, logging remains <strong>disabled</strong>.</li>
                            <li>A <strong>valid directory path</strong> enables logging, generating two separate log files:</li>
                            <ol>
                            <li><strong>Login attempts log:</strong> <code>auth.log</code> – Records failed login attempts.</li>
                            <li><strong>Spam detection log:</strong> <code>spam.log</code> – Logs suspicious form submissions.</li>
                            </ol>
                            </ol>

                            <br>Ensure the specified path is <strong>writable</strong> by the server and does not include a filename, as logs will be automatically managed within the chosen directory.
                            <br>If <code>auth.log</code> or <code>spam.log</code> already exist in the specified directory, they will be used for logging instead of creating new files.<br>
                " ),
                'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🛡'
            ),
            Option::POW_SAVE_CLEAN => new Option(
                __( 'Save clean messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                true,
                sprintf(__( "If you want to store your clean messages to the databse. You can see your saved clean messages <a href='%s'>here</a>", 'gdpr-compliant-recaptcha-for-all-forms' ), admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '💾'
            ),
            Option::POW_SAVE_SPAM => new Option(
                __( 'Save spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                true,
                sprintf( __( "If you want to check that only spam messages are blocked. You can see your saved spam messages <a href='%s'>here</a>", 'gdpr-compliant-recaptcha-for-all-forms' ), admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_SPAM ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '💾'
            ),
            Option::POW_SAVE_LOGIN => new Option(
                __( 'Save Logins', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                true,
                __( "If you don't want to save sucessfull wordpress-logins, just disable this option.", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🔒💾'
            ),
            Option::POW_FLAG_SAVE => new Option(
                __( 'Save spam messages with flag', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                true,
                __( "Indicates whether spam messages shall be saved with, or without flag <br> For testing whether the flagging works as desired, it may be usefull to save the messages with flags", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🚩💾'
            ),
            Option::POW_SAVE_IP => new Option(
                __( 'Save spam messages with IP', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                false,
                __( "<strong>Warning:</strong> If you save IP adresses of your users, this doesn't comply to the European data privacy act <b>GDPR</b>.", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🛡️💾'
            ),
            Option::POW_SKIP_FIELDS => new Option(
                __( 'Skip fields from saving', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                sprintf( __( "<strong>The purpose:</strong> Specify fields on specific sites, that you which to skip from saving with messages. It is recommended to use this option in order to skip password fields from beeing saved.
                    <br>     
                    <br><strong>How it works:</strong> To skip fields from beeing saved with messages, enter each combination of <em>site:field-name</em> in a new line.
                    <br>The fieldname has to be the specific technical fieldname of the field that you want to skip and the site name has to be the specific technical name of the specific site, containing the field.
                    <br>If you don't know the exact technical field names and sites, you can get them this way:
                        <br><ol>
                            <li>Tick the box for 'Save clean messages'</li>
                            <li>Save the options</li>
                            <li>Post a message from the respective site</li>
                            <li>Open the %sMessage inbox%s and the just received message respectively</li>
                            <li>Look for the field that you wish to skip from beeiong saved and take the name of the respective attribute without apostrophs</li>
                            <li>If your fieldname is nested, it may look a bit confusing (example: 'wpforms->fields->0->first' ). This is the case when your form builder is using a nested field structure. In this case the fieldname represents the field structure respectively. Nevertheless just copy the whole field name without the colon at the end.</li>
                            <li>Look for the attribute 'from_site' to get the technical name of the site. You just need to copy the unique part of the url (i.e. the specific site name without the domain or any parameters)</li>
                        </ol>
                    <br><strong>The format:</strong> <em>site:field-name</em>
                    <br>
                    <br><strong>Examples:</strong>
                    <br><u>Given site:</u> <em>www.your-domain.net/specific_site/?action=123</em>
                    <br><u>Given field name:</u> <em>pwd</em>
                    <br>
                    <br><u>Line to be added:</u> <em>/specific_site/:pwd</em>
                    ", 'gdpr-compliant-recaptcha-for-all-forms' ), '<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES .'">', '</a>' ) ,
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🚫▭'
            ),            
            Option::POW_MESSAGE_HEADS => new Option(
                __( 'Subject fields', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                sprintf( __( trim( "<strong>The purpose:</strong> Custom the subject fields for your different forms, in order to see meaningfull titles on your saved messages page.<br>
                <br>
                <strong>How it works:</strong> For each part of the the subject add a new line.
                <br>The fieldname has to be the specific technical fieldname of the message which you want to flag
                <br>If you don't know the exact technical fieldname of the respective field, you can get it this way:
                <br>
                <br><ol>
                    <li>Tick the box for 'Save clean messages'</li>
                    <li>Post a message from the respective form</li>
                    <li>Open the <a href='%s'>\"Messages\" inbox</a> and open your message that has been saved</li>
                    <li>Look for the field you want to use for flagging, and take the name of the respective attribute without apostrophs</li>
                </ol>
                <br><strong>Example for a subject composed of two parts:</strong>
                <br>
                <br><em>subject</em>
                <br><em>wpforms->fields->1</em>
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ), admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🔤'
            ),
            Option::POW_SAVE_CART => new Option(
                __( 'Save WooCommerce shopping carts', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                true,
                __("Specifies whether shopping carts from WooCommerce shall be saved as messages. If you get too many messages from shopping carts, you can disable this option.", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🛒'
            ),
            Option::POW_CRON_DELETE_INBOX => new Option(
                __( 'Automatic Message Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::INT,
                0,
                __( trim( "
                    Number of days after which messages from the inbox should be automatically deleted.
                    <br>
                    <br>Note: To disable this option, set the number to 0 or leave the field empty.
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🗑️✉️'
            ),
            Option::POW_CRON_DELETE_SPAM => new Option(
                __( 'Automatic Spam Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::INT,
                0,
                __( trim( "
                    Number of days after which messages from the spam inbox should be automatically deleted.
                    <br>
                    <br>Note: To disable this option, set the number to 0 or leave the field empty.
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🗑️📩'
            ),
            Option::POW_CRON_DELETE_TRASH => new Option(
                __( 'Automatic Trash Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::INT,
                0,
                __( trim( "
                    Number of days after which messages from the trash inbox should be automatically deleted.
                    <br>
                    <br>Note: To disable this option, set the number to 0 or leave the field empty.
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🗑️📨'
            ),
            Option::POW_APPLY_REST => new Option(
                __( 'Apply on REST-API', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                false,
                __( "This option improves the site-security a lot. <br><br><strong>But beware</strong>, several plugins use the REST-API for handshake-procedures, or plugin-maintenance by the vendor. In this case you can control the specific access via the whitelisting options one-by-one.", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🖥️'
            ),
            Option::POW_IP_WHITELIST => new Option(
                __( 'IP-Whitelist', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                __( "Add line by line and without seperator IPs, that you wish to whitelist. Example: <br> <br>192.0.0.1<br>241.x.x.xxx<br>...", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🌐'
            ),
            Option::POW_SITE_WHITELIST => new Option(
                __( 'Site-Whitelist', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                __( trim( "
                        Add each site that you whish to whitelist in a separat line and without the protocol ( i.e. without \"https://\" or \"http://\" ), that you wish to whitelist. 
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><em>dev.whistle-blower.net/?rest_route=/jetpack/v4/verify_registration/</em>
                        <br>...
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '📄'
            ),
            Option::POW_HIDE_ACTION => new Option(
                __( 'Hide actions', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                __( trim( "
                        Add line by line actions, that you wish not to be shown in the Analytic Box from <b>Analysis mode</b> 🔍.
                        <br>
                        <br><strong>Example:</strong> 
                        <br>
                        <br><em>heartbeat</em>
                    " ), 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '⚙️🚫'
            ),
            Option::POW_HIDE_PATTERN => new Option(
                __( 'Hide Patterns', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::TEXT,
                "",
                sprintf( __( trim( "
                        Administrate line by line actions, patterns that you wish not to be shown in the Analytic Box from <b>Analysis mode</b> 🔍.
                        <br>The easiest way to add the patterns is directly from the %sAnalytic Box%s.
                    " ), 'gdpr-compliant-recaptcha-for-all-forms'  ) , '<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS .'">', '</a>' ),
                __( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🔍🚫'
            ),
            Option::POW_MENU_POSITION => new Option(
                __( 'Messages Inbox Position', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::INT,
                0,
                __( trim( "
                    <strong>The purpose:</strong> Specifies on which position the messages inbox appears in the administration menu of Wordpress.
                    <br>
                    <br><strong>How it works:</strong> The default '0' means that the menu appears on the first position. The positioning number considers also submenu entries of wordpress. Thus a position like '40' in fact may result in a real position of 8.
                    <br>Therefore you have to try a bit with the figures to get your preferred position.
                    <br>If you want to hide the messages inbox, just set this option to '-1'.
                " ), 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Wordpress Administration', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '📌' //Number symbol
            ),
            Option::POW_DASHBOARD => new Option(
                __( 'Message counters on the Wordpress Dashboard', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::BOOL,
                true,
                __( "Show message counters on the Wordpress Dashboard", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Wordpress Administration', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '📊' //Dashboard symbol
            ),
            Option::POW_SALT => new Option(
                __( 'Salt', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::STRING,
                hash( 'sha256', date( "Y-m-d H:i:s.u" ) ),
                __( "Set this to a random string in order to give some unknown salt into the puzzle. It increases security, as it can't be guessed from client-side<br> By default, this salt is generated as a hash from the point in time of your installation", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🔑'
            ),
            Option::POW_TIME_WINDOW => new Option(
                __( 'Time Window', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::INT,
                10,
                __("The time a hash-puzzle is valid and has to be computed and solved anew", 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '⌛'
            ),
            Option::POW_DIFFICULTY => new Option(
                __( 'Difficulty', 'gdpr-compliant-recaptcha-for-all-forms' ),
                Option::INT,
                12,
                __( trim("
                        Set this to control the amount of computing power required to solve the hash-puzzle<br>
                        If you don't know about the concept of proof-of-work, don't change it<br>
                        Approximate number of hash guesses required for difficulty target of:<br>
                        <ol>
                            <li>Difficulty 1-4: 10</li>
                            <li>Difficulty 5-8: 100</li>
                            <li>Difficulty 9-12: 1,000</li>
                            <li>Difficulty 13-16: 10,000</li>
                            <li>Difficulty 17-20: 100,000</li>
                            <li>Difficulty 21-24: 1,000,000</li>
                            <li>Difficulty 25-28: 10,000,000</li>
                            <li>Difficulty 29-32: 100,000,000</li>
                        </ol>
                    " ), 'gdpr-compliant-recaptcha-for-all-forms' ),
                __( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
                '🧩'
            ),
        ];

        //Check whether the installation was done already
        if ( ! get_option( Option::POW_INSTALLED ) ){

            update_option( Option::POW_INSTALLED, true );

            foreach ( $this->options as $id => $option ) {

                update_option( $id, $option->getDefault() );

            }
        }
			
        //Name the plugin
        $this->plugin_name = __("GDPR-Compliant ReCaptcha",'gdpr-compliant-recaptcha-for-all-forms');

        $this->update_settings();

        foreach ( $this->options as $id => $option ) {

            $type = $option->getType();
            if( $type == Option::RoleDropDown ){
                // Retrieve the raw option value as an array
                $raw_option_value = get_option( $id, array() );
                // Filter the array values as strings

                $filtered_value = array_map(function($value) {
                    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
                }, $raw_option_value);
                $option->setValue( $filtered_value );
            } else {
                $filter = $this->get_option_filter( $type );
                $filtered_value = filter_var( get_option( $id ), $filter );
                $option->setValue( $type === Option::INT || $type === Option::BOOL ? intval( $filtered_value ) : strval( $filtered_value ) );
            }

        }

        $this->display_options();
    }

    /** Wenn the plugin is run
     */
    public function run()
    {
        add_filter( sprintf( 'plugin_action_links_%s', plugin_basename( __FILE__ ) ), [ $this, 'get_action_links'] );
        add_action( 'admin_menu', [ $this, 'admin_menu'] );
        add_action( 'admin_init', [ $this, 'prepare_options' ] );
        add_filter( 'plugin_action_links_' . GDPR_COMPLIANT_RECAPTCHA, [ $this, 'add_settings_link' ] );
    }

    /**  Get links for settings page
     * 
     */
    public function get_action_links( $links )
    {
        return array_merge( ['settings' => sprintf( '<a href="options-general.php%s">%s</a>', Option::PAGE_QUERY, __( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) )], $links );
    }

    /** Add the admin menu for the plugin
     *
     */
    public function admin_menu()
    {
        $page = add_submenu_page( 'options-general.php'
                        , $this->plugin_name
                        , __( 'ReCaptcha GDPR Compliant', 'gdpr-compliant-recaptcha-for-all-forms' )
                        , 'manage_options'
                        , Option::PREFIX . 'options'
                        , [ $this, 'options_page']
        );
        add_action( "admin_print_styles-{$page}", [ $this, 'enqueue_settings_page_ressources'] );
    }

    // Add a "Settings" link to the plugin action links
    function add_settings_link( $links ) {
        $url = get_admin_url() . "options-general.php?page=" . Option::PREFIX . 'options';
        $settings_link = '<a href="' . $url . '">' . __('Settings', 'gdpr-compliant-recaptcha-for-all-forms') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    /**Add style only for settings page */
    function enqueue_settings_page_ressources() {
        wp_enqueue_style( 'gdpr-settingsPageStyle' );
        wp_enqueue_script( 'gdpr-settingsPageScript' );
    }

    /** Iterates through each option for the settings page of the plugin in order to show the input fields
     * 
     */
    public function display_options()
    {
        $sections = [];
        foreach ( $this->options as $key => $option ) {
            $group = $option->getGroup();
            if ( ! in_array( $group, $sections ) ){
                $sections[] = $group;
                add_settings_section( 
                    Option::PREFIX . 'header_section' . trim( $group ),
                    '',
                    function() use($group) {
                        echo '<div href="#" class="gdpr-tab-link" data-tab-target="gdpr-tab-' . sanitize_title( $group ) . '">' . $group . '</div>';
                    },
                    Option::PREFIX . 'options',
                );
            }
        }
        // Iterate through each group to add fields
        foreach ($sections as $group) {
            foreach ( $this->options as $key => $option ) {
                if ($option->getGroup() === $group) {
                    $args = [
                                'key'  => $key,
                                'type' => $option->getType(),
                                'class' => 'recaptchaOption gdpr-tab-' . sanitize_title( $group ),
                                'id' => $key, 
                                'name' => $option->getName(),
                                'symbol' => $option->getSymbol(),
                    ];

                    $group = $option->getGroup();
                    //Suffix for the  follows in the dipsplay_input - function, as add_settings_field directly echoes
                    $html_prefix = '<div class="recaptchaOptionLeft">';
                    $html_sufix = '</div>';

                    add_settings_field( 
                        $key,
                        $html_prefix . $option->getName() . $html_sufix,
                        [ $this, 'display_input' ],
                        Option::PREFIX . 'options',
                        Option::PREFIX . 'header_section' . trim( $group ),
                        $args,
                    );

                    register_setting( Option::PREFIX . 'header_section', $key );
                }
            }
        }
        //Registers styles and scripts for the settings-page but don't enqueue it yet
        wp_register_style( 'gdpr-settingsPageStyle', plugins_url( '/css/style_admin.css', __DIR__ ), [], '1.0.2' );
        wp_register_script('gdpr-settingsPageScript', plugins_url('/scripts/recaptcha-gdpr-settings.js', __DIR__), [], '1.0', true);
        
        // Pass sections to JavaScript
        //wp_localize_script('gdpr-settingsPageScript', 'your_plugin_sections', $this->get_sections());        

        // Localize the script with the data
        $gdpr_settings_selection_value = isset( $_POST[ 'gdpr-settings-selection' ] ) ? $_POST[ 'gdpr-settings-selection' ] : 'gdpr-tab-most-relevant';
        wp_localize_script( 'gdpr-settingsPageScript', 'gdprSettingsSelection', array( 'value' => $gdpr_settings_selection_value ) );

    }

    /*A function to retrieve all groups of settings */
    public function get_sections() {
        $sections = [];
        foreach ($this->options as $key => $option) {
            $group = $option->getGroup();
            if (!in_array($group, $sections)) {
                $sections[] = $group;
            }
        }
        return $sections;
    }

    /** Retrieving the value for each option on the settings page for the plugin
     *
     */
    private function get_option_value( $id )
    {
        return isset($this->options[$id]) ? $this->options[$id]->getValue() : '';
    }

    /** Retrieving the hint for each option on the settings page for the plugin
     *
     */
    private function get_option_hint( $id )
    {
        $hint = $this->options[ $id ]->getHint();
        return isset( $hint ) ? $hint : '';
    }

    /** Insert the input fields on the admins page of the plugin
     *
     */
    public function display_input( $atts )
    {
        $key = $atts['key'];
        $type = $atts['type'];
        $val = $this->get_option_value( $key );
        $hint = $this->get_option_hint( $key );
        $symbol = $atts['symbol'];

        $allowed_html = array(
            'br' => array(),
            'ol' => array(),
            'ul' => array(),
            'li' => array(),
            'strong' => array(),
            'b' => array(),
            'u' => array(),
            'em' => array(),
            'a' => array(
                'href' => array(),
                'title' => array()
            ),
        );
        ?>
        <table class="recaptchaOptionRight">
            <tr>
                <td class="recaptchaOptionLeft" style="font-size: 40px;"><b><?php esc_attr_e( $symbol ); ?></b></td>
                <td>
        <?php
        if ( $type === Option::INT ) {
            ?>
                <input type="number" name="<?php esc_attr_e( $key ); ?>" class="regular-text" id="<?php esc_attr_e( $key ); ?>" value="<?php esc_attr_e( $val ); ?>" />
            <?php
        } else if ( $type === Option::STRING ) {
            ?>
                <input type="text" name="<?php esc_attr_e( $key ) ?>" class="regular-text" id="<?php esc_attr_e( $key ) ?>" value="<?php esc_attr_e( $val ) ?>" />
            <?php
        } else if ( $type === Option::TEXT ) {
            ?>
                <textarea name="<?php esc_attr_e( $key ); ?>" class="regular-text" id="<?php esc_attr_e( $key ); ?>" ><?php esc_html_e( $val ); ?></textarea>
            <?php
        } else if ( $type === Option::BOOL ){
            $checked = "";
            if ( $val ) {
                $val = "checked ";
            }
            ?>
                <input type="checkbox" name="<?php esc_attr_e( $key ); ?>" id="<?php esc_attr_e( $key ); ?>" <?php esc_attr_e( $val ); ?>/>
            <?php
        } else if ( $type === Option::RoleDropDown){
            // Get the saved value from the WordPress options
            $selected_roles = $val;
            $all_roles = get_editable_roles();
            
            ?>
            <select name="<?php esc_attr_e( $key ); ?>[]" multiple="multiple">
                <?php
                foreach ( $all_roles as $role_key => $role ) {
                    $selected = in_array( $role_key, $selected_roles ) ? 'selected' : '';
                    ?>
                    <option value="<?php esc_attr_e( $role_key ); ?>" <?php esc_attr_e( $selected ); ?>>
                        <?php esc_html_e( $role[ 'name' ] ); ?>
                    </option>
                    <?php
                }
                ?>
            </select>
            <?php
        }
        ?>
            </td>
            <td>
                <a class="hilfe_link" onClick="document.querySelector('#dialog_<?php esc_attr_e( $key ); ?>').style.display = 'inline';">help</a>
                <div class="hilfe_dialog" id="dialog_<?php esc_attr_e( $key ); ?>">
                    <a role="button" onClick="document.querySelector('#dialog_<?php esc_attr_e( $key ); ?>').style.display = 'none';" class="schliessen_button">x</a><br>
                    <?php echo( wp_kses( $hint, $allowed_html ) ); ?>
                </div>
            </td>
            </tr></table>
        <?php
    }

    /** Updating the values for the options
     * 
     */
    public function update_settings()
    {
        $postAction = strval( filter_input( INPUT_POST, self::RCM_ACTION, FILTER_SANITIZE_SPECIAL_CHARS ) );
        // If update and current user is allowed to manage options
        if ( $postAction === self::UPDATE && current_user_can( 'manage_options' ) ) {
            $hash = null;
    
            foreach ( $this->options as $key => $option ) {
                // Check if the input is an array or a single value
                $isArray = $option->getType() == Option::RoleDropDown;
    
                if ( $isArray ) {
                    // For arrays, filter as strings
                    $postValue = filter_input( INPUT_POST, $key, FILTER_DEFAULT, FILTER_REQUIRE_ARRAY );
                    $postValue ? array_map( 'sanitize_text_field', $postValue ) : [];
                } elseif ( $option->getType() === Option::TEXT || $option->getType() === Option::STRING ){
                    $postValue = stripslashes( wp_kses_post( $_POST[ $key ]  ) );
                } else {
                    // For single values, apply the specified filter
                    $postValue = filter_input( INPUT_POST, $key, $this->get_option_filter( $option->getType() ) );
                }
                if ( $postValue !== null && ( $isArray || $postValue !== false ) ) {
                    update_option( $key, $postValue );
    
                    if ( $isArray ) {
                        $hash .= implode( '', $postValue );
                    } elseif ( substr( $key, -strlen( '_key' ) ) === '_key' ) {
                        $hash .= $postValue;
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

    /** Filter special chars if not int
     * 
     */
    private function get_option_filter( $type )
    {
        $filter="";
        if ( $type === Option::INT ){
            $filter = FILTER_SANITIZE_NUMBER_INT;
        }else if ( $type === Option::BOOL ){
            $filter = FILTER_VALIDATE_BOOLEAN;
        }else{
            $filter = FILTER_SANITIZE_FULL_SPECIAL_CHARS;
        }
        return $filter;
    }

    /**
     * Drawing the options page for the plugin
     */
    public function options_page()
    {
        $review_link = '<a href="https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/reviews/#new-post">' . __( 'Help us and rate it','gdpr-compliant-recaptcha-for-all-forms' ) . '</a>';
        $faq_link = '<a href="https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/">' . __( 'Get help in the support forum','gdpr-compliant-recaptcha-for-all-forms' ) . '</a>';
        $line_break = '<br>';
        $checkmark = '<span class="large-checkmark">✓</span>';
        $smiley = '<span class="large-smiley">&#128578;</span>';
        $thinking_smiley = '<span class="large-smiley">&#129300;</span>';
        $message1 = __('%s The plugin is now active on all of your forms and logins.%s%s', 'gdpr-compliant-recaptcha-for-all-forms' );
        $message_with_links1 = sprintf( $message1, $checkmark, $line_break, $line_break );
        $message2 = __('%s Happy with the plugin? %s %s%s %s Problems, questions, hints, improvements? %s', 'gdpr-compliant-recaptcha-for-all-forms' );
        $message_with_links2 = sprintf( $message2, $smiley, $review_link, $line_break, $line_break, $thinking_smiley, $faq_link );
        ?>
        <script>
        // JavaScript to handle tab switching
        function showTab(tabId) {
          // Hide all tabs
          var tabs = document.querySelectorAll('.gdpr-tab-content');
          tabs.forEach(function(tab) {
            tab.style.display = 'none';
          });
    
          // Show the selected tab
          document.getElementById(tabId).style.display = 'block';
        }
        </script>
        <div class="recaptchaWrap">
            <h1><?php esc_html_e( $this->plugin_name.' - '.__( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) ) ?>
            </h1>
            <?php
                echo( $message_with_links2 );
            ?>
            <table>
                <tr>
                    <td>
                        <form class="settings-form" method="post" action="<?php esc_attr_e( Option::PAGE_QUERY ); ?>">
                            <?php
                            settings_fields( Option::PREFIX . 'header_section' );
                            do_settings_sections( Option::PREFIX . 'options' );
                            ?>
                            <input type="hidden" name="<?php esc_html_e(self::RCM_ACTION); ?>" value="<?php esc_attr_e(self::UPDATE); ?>">
                            <input type="hidden" id="gdpr-settings-selection" name="gdpr-settings-selection" value="">
                            <div id="submit-container">
                            <?php
                            submit_button();
                            ?>
                            </div>
                        </form>
                    </td>
                </tr>
            </table>
        </div>
        <?php
    }

}
?>