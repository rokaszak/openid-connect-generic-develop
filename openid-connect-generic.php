<?php
/**
 * Airomi Connect
 *
 * This plugin provides the ability to authenticate users with Identity
 * Providers using the OpenID Connect OAuth2 API with Authorization Code Flow.
 *
 * @package   OpenID_Connect_Generic
 * @category  General
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 * @link      https://airomi.lt
 *
 * @wordpress-plugin
 * Plugin Name:       Airomi Connect
 * Plugin URI:        https://airomi.lt
 * Description:       Connect to an OpenID Connect identity provider using Authorization Code Flow.
 * Version:           3.40.5
 * Requires at least: 5.0
 * Requires PHP:      7.4
 * Author:            Rokas Zakarauskas
 * Author URI:        https://airomi.lt
 * Text Domain:       daggerhart-openid-connect-generic
 * Domain Path:       /languages
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 */

class OpenID_Connect_Generic
{


	protected static $_instance = null;


	const VERSION = '3.40.5';


	private $settings;


	private $logger;


	private $client;


	public $client_wrapper;


	public function __construct(OpenID_Connect_Generic_Option_Settings $settings, OpenID_Connect_Generic_Option_Logger $logger)
	{
		$this->settings = $settings;
		$this->logger = $logger;
		self::$_instance = $this;
	}




	public function init()
	{

		$this->resolve_discovery_endpoints();

		$this->client = new OpenID_Connect_Generic_Client(
			$this->settings->client_id,
			$this->settings->client_secret,
			$this->settings->scope,
			$this->settings->endpoint_login,
			$this->settings->endpoint_userinfo,
			$this->settings->endpoint_token,
			$this->get_redirect_uri($this->settings),
			$this->settings->acr_values,
			$this->get_state_time_limit($this->settings),
			$this->logger
		);

		$this->client_wrapper = OpenID_Connect_Generic_Client_Wrapper::register($this->client, $this->settings, $this->logger);

		$this->upgrade();

		if (defined('WP_CLI') && WP_CLI) {
			return;
		}

		OpenID_Connect_Generic_Login_Form::register($this->settings, $this->client_wrapper);


		OpenID_Connect_Generic_Login_Initiator::register($this->client_wrapper, $this->logger);


		OpenID_Connect_Generic_Userinfo_Refresh::register($this->client_wrapper, $this->logger);


		if (
			class_exists('WooCommerce') &&
			(!empty($this->settings->enable_woocommerce_oidc) ||
			 !empty($this->settings->disable_woocommerce_password_auth) ||
			 !empty($this->settings->disable_woocommerce_edit_account_fields))
		) {
			OpenID_Connect_Generic_WooCommerce_Integration::register($this->settings, $this->client_wrapper);
		}


		OpenID_Connect_Generic_Bricks_Integration::register();


		OpenID_Connect_Generic_Magic_Link_Rest::register($this->settings, $this->logger, $this->client_wrapper);
		OpenID_Connect_Generic_Magic_Link_Consumer::register($this->settings, $this->logger, $this->client_wrapper);


		add_shortcode('openid_connect_generic_auth_url', array($this->client_wrapper, 'get_authentication_url'));


		add_action('openid-connect-generic-cron-daily', array($this, 'cron_states_garbage_collection'));

		if (is_admin()) {
			OpenID_Connect_Generic_Settings_Page::register($this->settings, $this->logger);
		}
	}


	const DISCOVERY_TRANSIENT = 'oidc_discovery_document';


	private function resolve_discovery_endpoints()
	{
		$discovery_url = $this->settings->discovery_url;
		if (empty($discovery_url)) {
			return;
		}


		$document = get_transient(self::DISCOVERY_TRANSIENT);

		if (false === $document) {

			$response = wp_remote_get(
				$discovery_url,
				array(
					'timeout' => 5,
					'sslverify' => !$this->settings->no_sslverify,
				)
			);

			if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
				$error_msg = is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code($response);
				$this->logger->log(
					array(
						'type' => 'discovery_fetch_failed',
						'discovery_url' => $discovery_url,
						'error' => $error_msg,
					),
					'discovery',
					null
				);

				$this->settings->discovery_failed = true;
				return;
			}

			$document = json_decode(wp_remote_retrieve_body($response), true);
			if (empty($document) || !is_array($document)) {
				$this->logger->log(
					array(
						'type' => 'discovery_invalid_json',
						'discovery_url' => $discovery_url,
					),
					'discovery',
					null
				);
				$this->settings->discovery_failed = true;
				return;
			}


			set_transient(self::DISCOVERY_TRANSIENT, $document, HOUR_IN_SECONDS);
		}


		$map = array(
			'authorization_endpoint' => 'endpoint_login',
			'token_endpoint' => 'endpoint_token',
			'userinfo_endpoint' => 'endpoint_userinfo',
			'end_session_endpoint' => 'endpoint_end_session',
		);

		foreach ($map as $discovery_key => $settings_key) {
			if (!empty($document[$discovery_key])) {
				$this->settings->$settings_key = $document[$discovery_key];
			}
		}
	}


	public function get_redirect_uri(OpenID_Connect_Generic_Option_Settings $settings)
	{
		$redirect_uri = admin_url('admin-ajax.php?action=openid-connect-authorize');

		if ($settings->alternate_redirect_uri) {
			$redirect_uri = site_url('/openid-connect-authorize');
		}

		return $redirect_uri;
	}


	public function get_state_time_limit(OpenID_Connect_Generic_Option_Settings $settings)
	{
		$state_time_limit = 180;

		if ($settings->state_time_limit) {
			$state_time_limit = intval($settings->state_time_limit);
		}

		return $state_time_limit;
	}


	public function enforce_privacy_redirect()
	{
		if ($this->settings->enforce_privacy && !is_user_logged_in()) {

			if (
				!defined('DOING_AJAX') ||
				!boolval(constant('DOING_AJAX')) ||
				!isset($_GET['action']) ||
				'openid-connect-authorize' != $_GET['action']
			) {
				auth_redirect();
			}
		}
	}


	public function enforce_privacy_feeds($content)
	{
		if ($this->settings->enforce_privacy && !is_user_logged_in()) {
			$content = __('Private site', 'daggerhart-openid-connect-generic');
		}
		return $content;
	}


	public static function create_token_table()
	{
		global $wpdb;

		$table_name = $wpdb->prefix . 'oidc_session_tokens';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			wp_session_token VARCHAR(64) NOT NULL,
			user_id BIGINT(20) UNSIGNED NOT NULL,
			access_token TEXT NOT NULL,
			refresh_token TEXT,
			id_token TEXT,
			expires_in INT UNSIGNED NOT NULL DEFAULT 0,
			token_issued_at INT UNSIGNED NOT NULL DEFAULT 0,
			session_expiration INT UNSIGNED NOT NULL DEFAULT 0,
			last_userinfo_check INT UNSIGNED NOT NULL DEFAULT 0,
			refresh_started_at INT UNSIGNED DEFAULT NULL,
			PRIMARY KEY (wp_session_token),
			KEY user_id (user_id),
			KEY session_expiration (session_expiration)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta($sql);
	}


	public static function maybe_add_refresh_started_at_column()
	{
		global $wpdb;
		$table_name = $wpdb->prefix . 'oidc_session_tokens';
		$column = $wpdb->get_row($wpdb->prepare(
			'SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s',
			DB_NAME,
			$table_name,
			'refresh_started_at'
		));
		if (empty($column)) {
			$wpdb->query("ALTER TABLE {$table_name} ADD COLUMN refresh_started_at INT UNSIGNED DEFAULT NULL");
		}
	}


	public static function cleanup_legacy_refresh_lock_options()
	{
		global $wpdb;
		$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_oidc_refresh_lock_%'");
	}


	public function upgrade()
	{
		$last_version = get_option('openid-connect-generic-plugin-version', 0);
		$settings = $this->settings;

		if (version_compare(self::VERSION, $last_version, '>')) {

			self::setup_cron_jobs();
			self::create_token_table();
			self::maybe_add_refresh_started_at_column();
			self::cleanup_legacy_refresh_lock_options();


			if (isset($settings->ep_login)) {
				$settings->endpoint_login = $settings->ep_login;
				$settings->endpoint_token = $settings->ep_token;
				$settings->endpoint_userinfo = $settings->ep_userinfo;

				unset($settings->ep_login, $settings->ep_token, $settings->ep_userinfo);
				$settings->save();
			}


			update_option('openid-connect-generic-plugin-version', self::VERSION);
		}
	}


	public function cron_states_garbage_collection()
	{
		global $wpdb;
		$states = $wpdb->get_col("SELECT `option_name` FROM {$wpdb->options} WHERE `option_name` LIKE '_transient_openid-connect-generic-state--%'");

		if (!empty($states)) {
			foreach ($states as $state) {
				$transient = str_replace('_transient_', '', $state);
				get_transient($transient);
			}
		}


		if (class_exists('OpenID_Connect_Generic_Token_Storage')) {
			$token_storage = new OpenID_Connect_Generic_Token_Storage($this->logger);
			$token_storage->cleanup_expired_tokens();
		}
	}


	public static function setup_cron_jobs()
	{
		if (!wp_next_scheduled('openid-connect-generic-cron-daily')) {
			wp_schedule_event(time(), 'hourly', 'openid-connect-generic-cron-daily');
		}
	}


	public static function activation()
	{
		self::setup_cron_jobs();
		self::create_token_table();
	}


	public static function deactivation()
	{
		wp_clear_scheduled_hook('openid-connect-generic-cron-daily');
	}


	public static function autoload($class)
	{
		$prefix = 'OpenID_Connect_Generic_';

		if (stripos($class, $prefix) !== 0) {
			return;
		}

		$filename = $class . '.php';


		if (false === strpos($filename, '\\')) {
			$filename = strtolower(str_replace('_', '-', $filename));
		} else {
			$filename = str_replace('\\', DIRECTORY_SEPARATOR, $filename);
		}

		$filepath = __DIR__ . '/includes/' . $filename;

		if (file_exists($filepath)) {
			require_once $filepath;
		}
	}


	public static function bootstrap()
	{

		spl_autoload_register(array('OpenID_Connect_Generic', 'autoload'));

		$settings = new OpenID_Connect_Generic_Option_Settings(

			array(

				'login_type' => defined('OIDC_LOGIN_TYPE') ? OIDC_LOGIN_TYPE : 'button',
				'client_id' => defined('OIDC_CLIENT_ID') ? OIDC_CLIENT_ID : '',
				'client_secret' => defined('OIDC_CLIENT_SECRET') ? OIDC_CLIENT_SECRET : '',
				'scope' => defined('OIDC_CLIENT_SCOPE') ? OIDC_CLIENT_SCOPE : '',
				'discovery_url' => defined('OIDC_DISCOVERY_URL') ? OIDC_DISCOVERY_URL : '',
				'failure_redirect_url' => '',
				'acr_values' => defined('OIDC_ACR_VALUES') ? OIDC_ACR_VALUES : '',


				'no_sslverify' => 0,
				'http_request_timeout' => 60,
				'identity_key' => 'preferred_username',
				'nickname_key' => 'preferred_username',
				'email_format' => '{email}',
				'displayname_format' => '',
				'enable_nickname_format' => 0,
				'nickname_format' => '{given_name}',
				'identify_with_username' => false,
				'state_time_limit' => 180,


				'enforce_privacy' => defined('OIDC_ENFORCE_PRIVACY') ? intval(OIDC_ENFORCE_PRIVACY) : 0,
				'alternate_redirect_uri' => 0,
				'token_refresh_enable' => 1,
				'link_existing_users' => defined('OIDC_LINK_EXISTING_USERS') ? intval(OIDC_LINK_EXISTING_USERS) : 0,
				'create_if_does_not_exist' => defined('OIDC_CREATE_IF_DOES_NOT_EXIST') ? intval(OIDC_CREATE_IF_DOES_NOT_EXIST) : 1,
				'redirect_user_back' => defined('OIDC_REDIRECT_USER_BACK') ? intval(OIDC_REDIRECT_USER_BACK) : 0,
				'enable_logging' => defined('OIDC_ENABLE_LOGGING') ? intval(OIDC_ENABLE_LOGGING) : 0,
				'log_limit' => defined('OIDC_LOG_LIMIT') ? intval(OIDC_LOG_LIMIT) : 1000,
				'disable_password_auth' => 0,
				'disable_password_reset' => 0,
				'enable_woocommerce_oidc' => 0,
				'disable_woocommerce_password_auth' => 0,
				'disable_woocommerce_edit_account_fields' => 0,
				'enable_magic_link' => 0,
				'login_button_text' => '',
				'login_button_image_id' => 0,
				'sync_userinfo_button_text' => '',


				'enable_role_mapping' => 0,
				'default_role' => 'subscriber',
				'role_claim_key' => '',
				'role_mappings' => array(),


				'userinfo_check_interval' => 600,
			)
		);

		$logger = new OpenID_Connect_Generic_Option_Logger('error', $settings->enable_logging, $settings->log_limit);

		$plugin = new self($settings, $logger);

		add_action('init', array($plugin, 'init'));


		add_action('template_redirect', array($plugin, 'enforce_privacy_redirect'), 0);
		add_filter('the_content_feed', array($plugin, 'enforce_privacy_feeds'), 999);
		add_filter('the_excerpt_rss', array($plugin, 'enforce_privacy_feeds'), 999);
		add_filter('comment_text_rss', array($plugin, 'enforce_privacy_feeds'), 999);
	}


	public static function instance()
	{
		if (null === self::$_instance) {
			self::bootstrap();
		}
		return self::$_instance;
	}
}

OpenID_Connect_Generic::instance();

register_activation_hook(__FILE__, array('OpenID_Connect_Generic', 'activation'));
register_deactivation_hook(__FILE__, array('OpenID_Connect_Generic', 'deactivation'));

require_once 'includes/functions.php';
