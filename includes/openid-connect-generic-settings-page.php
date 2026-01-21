<?php
/**
 * Plugin Admin settings page class.
 *
 * @package   OpenID_Connect_Generic
 * @category  Settings
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_Settings_Page class.
 *
 * Admin settings page.
 *
 * @package OpenID_Connect_Generic
 * @category  Settings
 */
class OpenID_Connect_Generic_Settings_Page {

	/**
	 * Local copy of the settings provided by the base plugin.
	 *
	 * @var OpenID_Connect_Generic_Option_Settings
	 */
	private $settings;

	/**
	 * Instance of the plugin logger.
	 *
	 * @var OpenID_Connect_Generic_Option_Logger
	 */
	private $logger;

	/**
	 * The controlled list of settings & associated defined during
	 * construction for i18n reasons.
	 *
	 * @var array
	 */
	private $settings_fields = array();

	/**
	 * Options page slug.
	 *
	 * @var string
	 */
	private $options_page_name = 'openid-connect-generic-settings';

	/**
	 * Options page settings group name.
	 *
	 * @var string
	 */
	private $settings_field_group;

	/**
	 * Settings page class constructor.
	 *
	 * @param OpenID_Connect_Generic_Option_Settings $settings The plugin settings object.
	 * @param OpenID_Connect_Generic_Option_Logger   $logger   The plugin logging class object.
	 */
	public function __construct( OpenID_Connect_Generic_Option_Settings $settings, OpenID_Connect_Generic_Option_Logger $logger ) {

		$this->settings             = $settings;
		$this->logger               = $logger;
		$this->settings_field_group = $this->settings->get_option_name() . '-group';

		$fields = $this->get_settings_fields();

		// Some simple pre-processing.
		foreach ( $fields as $key => &$field ) {
			$field['key']  = $key;
			$field['name'] = $this->settings->get_option_name() . '[' . $key . ']';
		}

		// Allow alterations of the fields.
		$this->settings_fields = $fields;
	}

	/**
	 * Hook the settings page into WordPress.
	 *
	 * @param OpenID_Connect_Generic_Option_Settings $settings A plugin settings object instance.
	 * @param OpenID_Connect_Generic_Option_Logger   $logger   A plugin logger object instance.
	 *
	 * @return void
	 */
	public static function register( OpenID_Connect_Generic_Option_Settings $settings, OpenID_Connect_Generic_Option_Logger $logger ) {
		$settings_page = new self( $settings, $logger );

		// Add our options page the the admin menu.
		add_action( 'admin_menu', array( $settings_page, 'admin_menu' ) );

		// Register our settings.
		add_action( 'admin_init', array( $settings_page, 'admin_init' ) );
	}

	/**
	 * Implements hook admin_menu to add our options/settings page to the
	 *  dashboard menu.
	 *
	 * @return void
	 */
	public function admin_menu() {
		add_options_page(
			__( 'Airomi Connect', 'daggerhart-openid-connect-generic' ),
			__( 'Airomi Connect', 'daggerhart-openid-connect-generic' ),
			'manage_options',
			$this->options_page_name,
			array( $this, 'settings_page' )
		);
	}

	/**
	 * Implements hook admin_init to register our settings.
	 *
	 * @return void
	 */
	public function admin_init() {
		register_setting(
			$this->settings_field_group,
			$this->settings->get_option_name(),
			array(
				$this,
				'sanitize_settings',
			)
		);

		add_settings_section(
			'client_settings',
			__( 'Client Settings', 'daggerhart-openid-connect-generic' ),
			array( $this, 'client_settings_description' ),
			$this->options_page_name
		);

		add_settings_section(
			'user_settings',
			__( 'WordPress User Settings', 'daggerhart-openid-connect-generic' ),
			array( $this, 'user_settings_description' ),
			$this->options_page_name
		);

		add_settings_section(
			'authorization_settings',
			__( 'Authorization Settings', 'daggerhart-openid-connect-generic' ),
			array( $this, 'authorization_settings_description' ),
			$this->options_page_name
		);

	add_settings_section(
		'log_settings',
		__( 'Log Settings', 'daggerhart-openid-connect-generic' ),
		array( $this, 'log_settings_description' ),
		$this->options_page_name
	);

	add_settings_section(
		'role_mapping_settings',
		__( 'Role Mapping Settings', 'daggerhart-openid-connect-generic' ),
		array( $this, 'role_mapping_settings_description' ),
		$this->options_page_name
	);

		// Preprocess fields and add them to the page.
		foreach ( $this->settings_fields as $key => $field ) {
			// Make sure each key exists in the settings array.
			if ( ! isset( $this->settings->{ $key } ) ) {
				$this->settings->{ $key } = null;
			}

		// Determine appropriate output callback.
		switch ( $field['type'] ) {
			case 'checkbox':
				$callback = 'do_checkbox';
				break;

			case 'select':
				$callback = 'do_select';
				break;

			case 'role_mappings_repeater':
				$callback = 'do_role_mappings_repeater';
				break;

			case 'image_picker':
				$callback = 'do_image_picker';
				break;

			case 'text':
			default:
				$callback = 'do_text_field';
				break;
		}

			// Add the field.
			add_settings_field(
				$key,
				$field['title'],
				array( $this, $callback ),
				$this->options_page_name,
				$field['section'],
				$field
			);
		}
	}

	/**
	 * Get the plugin settings fields definition.
	 *
	 * @return array
	 */
	private function get_settings_fields() {

		/**
		 * Simple settings fields have:
		 *
		 * - title
		 * - description
		 * - type ( checkbox | text | select )
		 * - section - settings/option page section ( client_settings | authorization_settings )
		 * - example (optional example will appear beneath description and be wrapped in <code>)
		 */
		$fields = array(
			'login_type'        => array(
				'title'       => __( 'Login Type', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Select how the client (login form) should provide login options.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'select',
				'options'     => array(
					'button' => __( 'OpenID Connect button on login form', 'daggerhart-openid-connect-generic' ),
					'auto'   => __( 'Auto Login - SSO', 'daggerhart-openid-connect-generic' ),
				),
				'disabled'    => defined( 'OIDC_LOGIN_TYPE' ),
				'section'     => 'client_settings',
			),
			'client_id'         => array(
				'title'       => __( 'Client ID', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'The ID this client will be recognized as when connecting the to Identity provider server.', 'daggerhart-openid-connect-generic' ),
				'example'     => 'my-wordpress-client-id',
				'type'        => 'text',
				'disabled'    => defined( 'OIDC_CLIENT_ID' ),
				'section'     => 'client_settings',
			),
			'client_secret'     => array(
				'title'       => __( 'Client Secret Key', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Arbitrary secret key the server expects from this client. Can be anything, but should be very unique.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'text',
				'disabled'    => defined( 'OIDC_CLIENT_SECRET' ),
				'section'     => 'client_settings',
			),
			'scope'             => array(
				'title'       => __( 'OpenID Scope', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Space separated list of scopes this client should access.', 'daggerhart-openid-connect-generic' ),
				'example'     => 'email profile openid offline_access',
				'type'        => 'text',
				'disabled'    => defined( 'OIDC_CLIENT_SCOPE' ),
				'section'     => 'client_settings',
			),
			'endpoint_login'    => array(
				'title'       => __( 'Login Endpoint URL', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Identify provider authorization endpoint.', 'daggerhart-openid-connect-generic' ),
				'example'     => 'https://example.com/oauth2/authorize',
				'type'        => 'text',
				'disabled'    => defined( 'OIDC_ENDPOINT_LOGIN_URL' ),
				'section'     => 'client_settings',
			),
			'endpoint_userinfo' => array(
				'title'       => __( 'Userinfo Endpoint URL', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Identify provider User information endpoint.', 'daggerhart-openid-connect-generic' ),
				'example'     => 'https://example.com/oauth2/UserInfo',
				'type'        => 'text',
				'disabled'    => defined( 'OIDC_ENDPOINT_USERINFO_URL' ),
				'section'     => 'client_settings',
			),
			'endpoint_token'    => array(
				'title'       => __( 'Token Validation Endpoint URL', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Identify provider token endpoint.', 'daggerhart-openid-connect-generic' ),
				'example'     => 'https://example.com/oauth2/token',
				'type'        => 'text',
				'disabled'    => defined( 'OIDC_ENDPOINT_TOKEN_URL' ),
				'section'     => 'client_settings',
			),
			'endpoint_end_session'    => array(
				'title'       => __( 'End Session Endpoint URL', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Identify provider logout endpoint.', 'daggerhart-openid-connect-generic' ),
				'example'     => 'https://example.com/oauth2/logout',
				'type'        => 'text',
				'disabled'    => defined( 'OIDC_ENDPOINT_LOGOUT_URL' ),
				'section'     => 'client_settings',
			),
			'acr_values'    => array(
				'title'       => __( 'ACR values', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Use a specific defined authentication contract from the IDP - optional.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'text',
				'disabled'    => defined( 'OIDC_ACR_VALUES' ),
				'section'     => 'client_settings',
			),
			'identity_key'     => array(
				'title'       => __( 'Identity Key', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Where in the user claim array to find the user\'s identification data. Possible standard values: preferred_username, name, or sub. If you\'re having trouble, use "sub".', 'daggerhart-openid-connect-generic' ),
				'example'     => 'preferred_username',
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'no_sslverify'      => array(
				'title'       => __( 'Disable SSL Verify', 'daggerhart-openid-connect-generic' ),
				// translators: %1$s HTML tags for layout/styles, %2$s closing HTML tag for styles.
				'description' => sprintf( __( 'Do not require SSL verification during authorization. The OAuth extension uses curl to make the request. By default CURL will generally verify the SSL certificate to see if its valid an issued by an accepted CA. This setting disabled that verification.%1$sNot recommended for production sites.%2$s', 'daggerhart-openid-connect-generic' ), '<br><strong>', '</strong>' ),
				'type'        => 'checkbox',
				'section'     => 'client_settings',
			),
			'http_request_timeout'      => array(
				'title'       => __( 'HTTP Request Timeout', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Set the timeout for requests made to the IDP. Default value is 5.', 'daggerhart-openid-connect-generic' ),
				'example'     => 30,
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'enforce_privacy'   => array(
				'title'       => __( 'Enforce Privacy', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Require users be logged in to see the site.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_ENFORCE_PRIVACY' ),
				'section'     => 'authorization_settings',
			),
			'alternate_redirect_uri'   => array(
				'title'       => __( 'Alternate Redirect URI', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Provide an alternative redirect route. Useful if your server is causing issues with the default admin-ajax method. You must flush rewrite rules after changing this setting. This can be done by saving the Permalinks settings page.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'checkbox',
				'section'     => 'authorization_settings',
			),
			'nickname_key'     => array(
				'title'       => __( 'Nickname Key', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Where in the user claim array to find the user\'s nickname. Possible standard values: preferred_username, name, or sub.', 'daggerhart-openid-connect-generic' ),
				'example'     => 'preferred_username',
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'email_format'     => array(
				'title'       => __( 'Email Formatting', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'String from which the user\'s email address is built. Specify "{email}" as long as the user claim contains an email claim.', 'daggerhart-openid-connect-generic' ),
				'example'     => '{email}',
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'displayname_format'     => array(
				'title'       => __( 'Display Name Formatting', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'String from which the user\'s display name is built.', 'daggerhart-openid-connect-generic' ),
				'example'     => '{given_name} {family_name}',
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'identify_with_username'     => array(
				'title'       => __( 'Identify with User Name', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'If checked, the user\'s identity will be determined by the user name instead of the email address.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'checkbox',
				'section'     => 'client_settings',
			),
			'state_time_limit'     => array(
				'title'       => __( 'State time limit', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'State valid time in seconds. Defaults to 180', 'daggerhart-openid-connect-generic' ),
				'type'        => 'number',
				'section'     => 'client_settings',
			),
			'token_refresh_enable'   => array(
				'title'       => __( 'Enable Refresh Token', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'If checked, support refresh tokens used to obtain access tokens from supported IDPs.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'checkbox',
				'section'     => 'client_settings',
			),
			'link_existing_users'   => array(
				'title'       => __( 'Link Existing Users', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'If a WordPress account already exists with the same identity as a newly-authenticated user over OpenID Connect, login as that user instead of generating an error.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_LINK_EXISTING_USERS' ),
				'section'     => 'user_settings',
			),
			'create_if_does_not_exist'   => array(
				'title'       => __( 'Create user if does not exist', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'If the user identity is not linked to an existing WordPress user, it is created. If this setting is not enabled, and if the user authenticates with an account which is not linked to an existing WordPress user, then the authentication will fail.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_CREATE_IF_DOES_NOT_EXIST' ),
				'section'     => 'user_settings',
			),
		'redirect_user_back'   => array(
			'title'       => __( 'Redirect Back to Origin Page', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'After a successful OpenID Connect authentication, this will redirect the user back to the page on which they clicked the OpenID Connect login button. This will cause the login process to proceed in a traditional WordPress fashion. For example, users logging in through the default wp-login.php page would end up on the WordPress Dashboard and users logging in through the WooCommerce "My Account" page would end up on their account page.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'checkbox',
			'disabled'    => defined( 'OIDC_REDIRECT_USER_BACK' ),
			'section'     => 'user_settings',
		),
			'enable_logging'    => array(
				'title'       => __( 'Enable Logging', 'daggerhart-openid-connect-generic' ),
				'description' => __( 'Very simple log messages for debugging purposes.', 'daggerhart-openid-connect-generic' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_ENABLE_LOGGING' ),
				'section'     => 'log_settings',
			),
		'log_limit'         => array(
			'title'       => __( 'Log Limit', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Number of items to keep in the log. These logs are stored as an option in the database, so space is limited.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'number',
			'disabled'    => defined( 'OIDC_LOG_LIMIT' ),
			'section'     => 'log_settings',
		),
		'enable_role_mapping'   => array(
			'title'       => __( 'Enable Role Mapping', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Enable mapping OIDC claim values to WordPress roles.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'checkbox',
			'section'     => 'role_mapping_settings',
		),
		'default_role'          => array(
			'title'       => __( 'Default Role', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Default WordPress role to assign when no claim mapping matches or role mapping is disabled.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'select',
			'options'     => $this->get_wordpress_roles(),
			'section'     => 'role_mapping_settings',
		),
		'role_claim_key'        => array(
			'title'       => __( 'Role Claim Key', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'The claim key to read role values from (e.g., "roles", "info.permissions", "groups").', 'daggerhart-openid-connect-generic' ),
			'example'     => 'info.permissions',
			'type'        => 'text',
			'section'     => 'role_mapping_settings',
		),
		'role_mappings'         => array(
			'title'       => __( 'Role Mappings', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Map OIDC claim values to WordPress roles. The first matching claim value will be used.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'role_mappings_repeater',
			'section'     => 'role_mapping_settings',
		),
		'userinfo_check_interval'   => array(
			'title'       => __( 'Token Validation Interval', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'How often (in seconds) to validate access token via userinfo endpoint. Default: 600 seconds (10 minutes). Set to 0 to disable periodic validation.', 'daggerhart-openid-connect-generic' ),
			'example'     => '600',
			'type'        => 'number',
			'section'     => 'user_settings',
		),
		'disable_password_auth'   => array(
			'title'       => __( 'Disable Password Authentication', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Completely disable WordPress password-based authentication. Users can ONLY login via OpenID Connect. <strong>Warning: Ensure OIDC is properly configured before enabling. Application Passwords for REST API/XML-RPC will continue to work.</strong>', 'daggerhart-openid-connect-generic' ),
			'type'        => 'checkbox',
			'section'     => 'authorization_settings',
		),
		'disable_password_reset'   => array(
			'title'       => __( 'Disable Password Reset', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Disable password reset functionality including lost password forms and reset links.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'checkbox',
			'section'     => 'authorization_settings',
		),
		'enable_woocommerce_oidc'   => array(
			'title'       => __( 'Enable WooCommerce OIDC Button', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Add OpenID Connect login button to WooCommerce login forms. Only applies if WooCommerce is active.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'checkbox',
			'section'     => 'authorization_settings',
		),
		'disable_woocommerce_password_auth'   => array(
			'title'       => __( 'Disable WooCommerce Password Login', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Disable WooCommerce password-based login forms. Users can ONLY use OpenID Connect for WooCommerce. Requires "Enable WooCommerce OIDC Button" to be enabled.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'checkbox',
			'section'     => 'authorization_settings',
		),
		'login_button_text'   => array(
			'title'       => __( 'Login Button Text', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Customize the text displayed on the OpenID Connect login button.', 'daggerhart-openid-connect-generic' ),
			'example'     => 'Login with OpenID Connect',
			'type'        => 'text',
			'section'     => 'client_settings',
		),
		'login_button_image_id'   => array(
			'title'       => __( 'Login Button Logo', 'daggerhart-openid-connect-generic' ),
			'description' => __( 'Optional logo image to display on the left side of the login button.', 'daggerhart-openid-connect-generic' ),
			'type'        => 'image_picker',
			'section'     => 'client_settings',
		),
	);

	return apply_filters( 'openid-connect-generic-settings-fields', $fields );
	}

	/**
	 * Sanitization callback for settings/option page.
	 *
	 * @param array $input The submitted settings values.
	 *
	 * @return array
	 */
	public function sanitize_settings( $input ) {
		$options = array();

		// Loop through settings fields to control what we're saving.
		foreach ( $this->settings_fields as $key => $field ) {
			// Special handling for role_mappings repeater.
			if ( 'role_mappings' === $key ) {
				$options[ $key ] = array();
				if ( isset( $input[ $key ] ) && is_array( $input[ $key ] ) ) {
					foreach ( $input[ $key ] as $mapping ) {
						// Only save mappings that have both claim value and role set.
						if ( ! empty( $mapping['claim_value'] ) && ! empty( $mapping['wp_role'] ) ) {
							$options[ $key ][] = array(
								'claim_value' => sanitize_text_field( $mapping['claim_value'] ),
								'wp_role'     => sanitize_text_field( $mapping['wp_role'] ),
							);
						}
					}
				}
			} elseif ( isset( $input[ $key ] ) ) {
				$options[ $key ] = sanitize_text_field( trim( $input[ $key ] ) );
			} else {
				$options[ $key ] = '';
			}
		}

		return $options;
	}

	/**
	 * Output the options/settings page.
	 *
	 * @return void
	 */
	public function settings_page() {
		wp_enqueue_style( 'daggerhart-openid-connect-generic-admin', plugin_dir_url( __DIR__ ) . 'css/styles-admin.css', array(), OpenID_Connect_Generic::VERSION, 'all' );
		wp_enqueue_script( 'daggerhart-openid-connect-generic-admin', plugin_dir_url( __DIR__ ) . 'js/settings-admin.js', array( 'jquery' ), OpenID_Connect_Generic::VERSION, true );
		wp_enqueue_media();

		$redirect_uri = admin_url( 'admin-ajax.php?action=openid-connect-authorize' );

		if ( $this->settings->alternate_redirect_uri ) {
			$redirect_uri = site_url( '/openid-connect-authorize' );
		}
		?>
		<div class="wrap">
			<h2><?php print esc_html( get_admin_page_title() ); ?></h2>

			<form method="post" action="options.php">
				<?php
				settings_fields( $this->settings_field_group );
				do_settings_sections( $this->options_page_name );
				submit_button();

				// Simple debug to view settings array.
				if ( isset( $_GET['debug'] ) ) {
					var_dump( $this->settings->get_values() );
				}
				?>
			</form>

			<h4><?php esc_html_e( 'Notes', 'daggerhart-openid-connect-generic' ); ?></h4>

			<p class="description">
				<strong><?php esc_html_e( 'Redirect URI', 'daggerhart-openid-connect-generic' ); ?></strong>
				<code><?php print esc_url( $redirect_uri ); ?></code>
			</p>
			<p class="description">
				<strong><?php esc_html_e( 'Login Button Shortcode', 'daggerhart-openid-connect-generic' ); ?></strong>
				<code>[openid_connect_generic_login_button]</code>
			</p>
			<p class="description">
				<strong><?php esc_html_e( 'Authentication URL Shortcode', 'daggerhart-openid-connect-generic' ); ?></strong>
				<code>[openid_connect_generic_auth_url]</code>
			</p>

			<?php if ( $this->settings->enable_logging ) { ?>
				<h2><?php esc_html_e( 'Logs', 'daggerhart-openid-connect-generic' ); ?></h2>
				<div id="logger-table-wrapper">
					<?php print wp_kses_post( $this->logger->get_logs_table() ); ?>
				</div>

			<?php } ?>
		</div>
		<?php
	}

	/**
	 * Output a standard text field.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_text_field( $field ) {
		?>
		<input type="<?php print esc_attr( $field['type'] ); ?>"
			id="<?php print esc_attr( $field['key'] ); ?>"
			class="large-text<?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) ? ' disabled' : ''; ?>"
			name="<?php print esc_attr( $field['name'] ); ?>"
			<?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) ? ' disabled' : ''; ?>
			value="<?php print esc_attr( $this->settings->{ $field['key'] } ); ?>">
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output a checkbox for a boolean setting.
	 *  - hidden field is default value so we don't have to check isset() on save.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_checkbox( $field ) {
		$hidden_value = 0;
		if ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) {
			$hidden_value = intval( $this->settings->{ $field['key'] } );
		}
		?>
		<input type="hidden" name="<?php print esc_attr( $field['name'] ); ?>" value="<?php print esc_attr( strval( $hidden_value ) ); ?>">
		<input type="checkbox"
			   id="<?php print esc_attr( $field['key'] ); ?>"
				 name="<?php print esc_attr( $field['name'] ); ?>"
				 <?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) ? ' disabled="disabled"' : ''; ?>
			   value="1"
			<?php checked( $this->settings->{ $field['key'] }, 1 ); ?>>
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output a select control.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_select( $field ) {
		$current_value = isset( $this->settings->{ $field['key'] } ) ? $this->settings->{ $field['key'] } : '';
		?>
		<select
			id="<?php print esc_attr( $field['key'] ); ?>"
			name="<?php print esc_attr( $field['name'] ); ?>"
			<?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) ? ' disabled' : ''; ?>
			>
			<?php foreach ( $field['options'] as $value => $text ) : ?>
				<option value="<?php print esc_attr( $value ); ?>" <?php selected( $value, $current_value ); ?>><?php print esc_html( $text ); ?></option>
			<?php endforeach; ?>
		</select>
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output an image picker field with media library integration.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_image_picker( $field ) {
		$image_id = isset( $this->settings->{ $field['key'] } ) ? intval( $this->settings->{ $field['key'] } ) : 0;
		$image_url = '';
		
		if ( $image_id ) {
			$image_url = wp_get_attachment_image_url( $image_id, 'thumbnail' );
		}
		?>
		<div class="oidc-image-picker-wrapper">
			<input type="hidden" 
				   id="<?php print esc_attr( $field['key'] ); ?>"
				   name="<?php print esc_attr( $field['name'] ); ?>"
				   value="<?php print esc_attr( $image_id ); ?>"
				   class="oidc-image-id">
			
			<div class="oidc-image-preview" style="margin-bottom: 10px;">
				<?php if ( $image_url ) : ?>
					<img src="<?php echo esc_url( $image_url ); ?>" style="max-width: 150px; height: auto; display: block;">
				<?php endif; ?>
			</div>
			
			<button type="button" 
					class="button oidc-select-image"
					data-field-id="<?php print esc_attr( $field['key'] ); ?>">
				<?php esc_html_e( 'Select Image', 'daggerhart-openid-connect-generic' ); ?>
			</button>
			
			<?php if ( $image_id ) : ?>
				<button type="button" 
						class="button oidc-remove-image"
						data-field-id="<?php print esc_attr( $field['key'] ); ?>">
					<?php esc_html_e( 'Remove Image', 'daggerhart-openid-connect-generic' ); ?>
				</button>
			<?php endif; ?>
		</div>
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output the field description, and example if present.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_field_description( $field ) {
		?>
		<p class="description">
			<?php print wp_kses_post( $field['description'] ); ?>
			<?php if ( isset( $field['example'] ) ) : ?>
				<br/><strong><?php esc_html_e( 'Example', 'daggerhart-openid-connect-generic' ); ?>: </strong>
				<code><?php print esc_html( $field['example'] ); ?></code>
			<?php endif; ?>
		</p>
		<?php
	}

	/**
	 * Get all WordPress roles as an associative array.
	 *
	 * @return array
	 */
	private function get_wordpress_roles() {
		$wp_roles = wp_roles();
		$roles    = array();

		foreach ( $wp_roles->roles as $slug => $role ) {
			$roles[ $slug ] = $role['name'];
		}

		return $roles;
	}

	/**
	 * Output the role mappings repeater field.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_role_mappings_repeater( $field ) {
		$mappings  = isset( $this->settings->{ $field['key'] } ) ? $this->settings->{ $field['key'] } : array();
		$wp_roles  = $this->get_wordpress_roles();
		$field_name = $field['name'];
		?>
		<div class="oidc-role-mappings-repeater">
			<div class="oidc-role-mappings-rows">
				<?php
				if ( ! empty( $mappings ) && is_array( $mappings ) ) :
					foreach ( $mappings as $index => $mapping ) :
						$claim_value = isset( $mapping['claim_value'] ) ? $mapping['claim_value'] : '';
						$wp_role     = isset( $mapping['wp_role'] ) ? $mapping['wp_role'] : '';
						?>
						<div class="oidc-role-mapping-row">
							<input type="text"
								   class="oidc-claim-value"
								   name="<?php echo esc_attr( $field_name ); ?>[<?php echo esc_attr( $index ); ?>][claim_value]"
								   value="<?php echo esc_attr( $claim_value ); ?>"
								   placeholder="<?php esc_attr_e( 'Claim value (e.g., info:admin)', 'daggerhart-openid-connect-generic' ); ?>">
							<span class="oidc-arrow">→</span>
							<select name="<?php echo esc_attr( $field_name ); ?>[<?php echo esc_attr( $index ); ?>][wp_role]"
									class="oidc-wp-role">
								<option value=""><?php esc_html_e( 'Select Role', 'daggerhart-openid-connect-generic' ); ?></option>
								<?php foreach ( $wp_roles as $role_slug => $role_name ) : ?>
									<option value="<?php echo esc_attr( $role_slug ); ?>" <?php selected( $role_slug, $wp_role ); ?>>
										<?php echo esc_html( $role_name ); ?>
									</option>
								<?php endforeach; ?>
							</select>
							<button type="button" class="button oidc-remove-row"><?php esc_html_e( 'Remove', 'daggerhart-openid-connect-generic' ); ?></button>
						</div>
						<?php
					endforeach;
				endif;
				?>
			</div>
			<button type="button" class="button oidc-add-row"><?php esc_html_e( 'Add Mapping', 'daggerhart-openid-connect-generic' ); ?></button>

			<!-- Template row for new mappings -->
			<script type="text/template" id="oidc-role-mapping-row-template">
				<div class="oidc-role-mapping-row">
					<input type="text"
						   class="oidc-claim-value"
						   name="<?php echo esc_attr( $field_name ); ?>[{{INDEX}}][claim_value]"
						   value=""
						   placeholder="<?php esc_attr_e( 'Claim value (e.g., info:admin)', 'daggerhart-openid-connect-generic' ); ?>">
					<span class="oidc-arrow">→</span>
					<select name="<?php echo esc_attr( $field_name ); ?>[{{INDEX}}][wp_role]"
							class="oidc-wp-role">
						<option value=""><?php esc_html_e( 'Select Role', 'daggerhart-openid-connect-generic' ); ?></option>
						<?php foreach ( $wp_roles as $role_slug => $role_name ) : ?>
							<option value="<?php echo esc_attr( $role_slug ); ?>">
								<?php echo esc_html( $role_name ); ?>
							</option>
						<?php endforeach; ?>
					</select>
					<button type="button" class="button oidc-remove-row"><?php esc_html_e( 'Remove', 'daggerhart-openid-connect-generic' ); ?></button>
				</div>
			</script>
		</div>
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output the 'Client Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function client_settings_description() {
		esc_html_e( 'Enter your OpenID Connect identity provider settings.', 'daggerhart-openid-connect-generic' );
	}

	/**
	 * Output the 'WordPress User Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function user_settings_description() {
		esc_html_e( 'Modify the interaction between OpenID Connect and WordPress users.', 'daggerhart-openid-connect-generic' );
	}

	/**
	 * Output the 'Authorization Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function authorization_settings_description() {
		esc_html_e( 'Control the authorization mechanics of the site.', 'daggerhart-openid-connect-generic' );
	}

	/**
	 * Output the 'Log Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function log_settings_description() {
		esc_html_e( 'Log information about login attempts through Airomi Connect.', 'daggerhart-openid-connect-generic' );
	}

	/**
	 * Output the 'Role Mapping Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function role_mapping_settings_description() {
		esc_html_e( 'Configure role mapping from OIDC claims to WordPress roles.', 'daggerhart-openid-connect-generic' );
	}
}
