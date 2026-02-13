<?php
/**
 * Plugin OIDC/oAuth client warpper class.
 *
 * @package   OpenID_Connect_Generic
 * @category  Authentication
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_Client_Wrapper class.
 *
 * Plugin OIDC/oAuth client wrapper class.
 *
 * @package  OpenID_Connect_Generic
 * @category Authentication
 */
class OpenID_Connect_Generic_Client_Wrapper
{

	/**
	 * The user redirect cookie key.
	 *
	 * @deprecated Redirection should be done via state transient and not cookies.
	 *
	 * @var string
	 */
	const COOKIE_REDIRECT_KEY = 'openid-connect-generic-redirect';

	/**
	 * The client object instance.
	 *
	 * @var OpenID_Connect_Generic_Client
	 */
	private $client;

	/**
	 * The settings object instance.
	 *
	 * @var OpenID_Connect_Generic_Option_Settings
	 */
	private $settings;

	/**
	 * The logger object instance.
	 *
	 * @var OpenID_Connect_Generic_Option_Logger
	 */
	private $logger;

	/**
	 * The token storage object instance.
	 *
	 * @var OpenID_Connect_Generic_Token_Storage
	 */
	private $token_storage;

	/**
	 * The return error onject.
	 *
	 * @example WP_Error if there was a problem, or false if no error
	 *
	 * @var bool|WP_Error
	 */
	private $error = false;

	/**
	 * Inject necessary objects and services into the client.
	 *
	 * @param OpenID_Connect_Generic_Client          $client   A plugin client object instance.
	 * @param OpenID_Connect_Generic_Option_Settings $settings A plugin settings object instance.
	 * @param OpenID_Connect_Generic_Option_Logger   $logger   A plugin logger object instance.
	 */
	public function __construct(OpenID_Connect_Generic_Client $client, OpenID_Connect_Generic_Option_Settings $settings, OpenID_Connect_Generic_Option_Logger $logger)
	{
		$this->client = $client;
		$this->settings = $settings;
		$this->logger = $logger;
		$this->token_storage = new OpenID_Connect_Generic_Token_Storage($logger);
	}

	/**
	 * Hook the client into WordPress.
	 *
	 * @param \OpenID_Connect_Generic_Client          $client   The plugin client instance.
	 * @param \OpenID_Connect_Generic_Option_Settings $settings The plugin settings instance.
	 * @param \OpenID_Connect_Generic_Option_Logger   $logger   The plugin logger instance.
	 *
	 * @return \OpenID_Connect_Generic_Client_Wrapper
	 */
	public static function register(OpenID_Connect_Generic_Client $client, OpenID_Connect_Generic_Option_Settings $settings, OpenID_Connect_Generic_Option_Logger $logger)
	{
		$client_wrapper = new self($client, $settings, $logger);

		// Hook token validation to wp_loaded (runs after init, when sessions are available).
		add_action('wp_loaded', array($client_wrapper, 'ensure_tokens_still_fresh'), 1);

		// Clean up token on logout.
		add_action('wp_logout', array($client_wrapper, 'cleanup_token_on_logout'), 10);

		// Integrated logout - intercept before WordPress logout happens.
		if ($settings->endpoint_end_session) {
			add_filter('allowed_redirect_hosts', array($client_wrapper, 'update_allowed_redirect_hosts'), 99, 1);
			add_action('login_init', array($client_wrapper, 'intercept_logout_redirect'), 1);
			add_action('wp', array($client_wrapper, 'handle_logout_return'), 1);
		}

		// Alter the requests according to settings.
		add_filter('openid-connect-generic-alter-request', array($client_wrapper, 'alter_request'), 10, 2);

		if (is_admin()) {
			/*
			 * Use the ajax url to handle processing authorization without any html output
			 * this callback will occur when then IDP returns with an authenticated value
			 */
			add_action('wp_ajax_openid-connect-authorize', array($client_wrapper, 'authentication_request_callback'));
			add_action('wp_ajax_nopriv_openid-connect-authorize', array($client_wrapper, 'authentication_request_callback'));
		}

		if ($settings->alternate_redirect_uri) {
			// Provide an alternate route for authentication_request_callback.
			add_rewrite_rule('^openid-connect-authorize/?', 'index.php?openid-connect-authorize=1', 'top');
			add_rewrite_tag('%openid-connect-authorize%', '1');
			add_action('parse_request', array($client_wrapper, 'alternate_redirect_uri_parse_request'));
		}

		return $client_wrapper;
	}

	/**
	 * Implements WordPress parse_request action.
	 *
	 * @param WP_Query $query The WordPress query object.
	 *
	 * @return void
	 */
	public function alternate_redirect_uri_parse_request($query)
	{
		if (
			isset($query->query_vars['openid-connect-authorize']) &&
			'1' === $query->query_vars['openid-connect-authorize']
		) {
			$this->authentication_request_callback();
			exit;
		}
	}

	/**
	 * Get the client login redirect.
	 *
	 * @return string
	 */
	public function get_redirect_to()
	{
		/*
		 * @var WP $wp
		 */
		global $wp;

		if (isset($GLOBALS['pagenow']) && 'wp-login.php' == $GLOBALS['pagenow'] && isset($_GET['action']) && 'logout' === $_GET['action']) {
			return '';
		}

		// Default redirect to the homepage.
		$redirect_url = home_url();

		// If using the login form, default redirect to the admin dashboard.
		if (isset($GLOBALS['pagenow']) && 'wp-login.php' == $GLOBALS['pagenow']) {
			$redirect_url = admin_url();
		}

		// Honor Core WordPress & other plugin redirects.
		if (isset($_REQUEST['redirect_to'])) {
			$redirect_url = esc_url_raw(wp_unslash($_REQUEST['redirect_to']));
		}

		// Capture the current URL if set to redirect back to origin page.
		if ($this->settings->redirect_user_back) {
			if (!empty($wp->query_string)) {
				$redirect_url = home_url('?' . $wp->query_string);
			}
			if (!empty($wp->request)) {
				$redirect_url = home_url(add_query_arg(null, null));
				// @phpstan-ignore-next-line
				if ($wp->did_permalink) {
					$redirect_url = home_url(add_query_arg($_GET, trailingslashit($wp->request)));
				}
			}
		}

		// This hook is being deprecated with the move away from cookies.
		$redirect_url = apply_filters_deprecated(
			'openid-connect-generic-cookie-redirect-url',
			array($redirect_url),
			'3.8.2',
			'openid-connect-generic-client-redirect-to'
		);

		// This is the new hook to use with the transients version of redirection.
		return apply_filters('openid-connect-generic-client-redirect-to', $redirect_url);
	}

	/**
	 * Create a single use authentication url
	 *
	 * @param array<string> $atts An optional array of override/feature attributes.
	 *
	 * @return string
	 */
	public function get_authentication_url($atts = array())
	{

		$atts = shortcode_atts(
			array(
				'endpoint_login' => $this->settings->endpoint_login,
				'scope' => $this->settings->scope,
				'client_id' => $this->settings->client_id,
				'redirect_uri' => $this->client->get_redirect_uri(),
				'redirect_to' => $this->get_redirect_to(),
				'acr_values' => $this->settings->acr_values,
			),
			$atts,
			'openid_connect_generic_auth_url'
		);

		// Validate the redirect to value to prevent a redirection attack.
		if (!empty($atts['redirect_to'])) {
			$atts['redirect_to'] = wp_validate_redirect($atts['redirect_to'], home_url());
		}

		$separator = '?';
		if (stripos($this->settings->endpoint_login, '?') !== false) {
			$separator = '&';
		}

		$url_format = '%1$s%2$sresponse_type=code&scope=%3$s&client_id=%4$s&state=%5$s&redirect_uri=%6$s';
		if (!empty($atts['acr_values'])) {
			$url_format .= '&acr_values=%7$s';
		}

		$url = sprintf(
			$url_format,
			$atts['endpoint_login'],
			$separator,
			rawurlencode($atts['scope']),
			rawurlencode($atts['client_id']),
			$this->client->new_state($atts['redirect_to']),
			rawurlencode($atts['redirect_uri']),
			rawurlencode($atts['acr_values'])
		);

		$url = apply_filters('openid-connect-generic-auth-url', $url);
		return $url;
	}

	/**
	 * Get formatted string with access token and WP session expiry info for logging.
	 *
	 * @param int   $user_id            The user ID.
	 * @param array $token_response     The token response with expires_in and time.
	 *
	 * @return string Formatted expiry information.
	 */
	private function get_expiry_info_for_logging($user_id, $token_response = null)
	{
		// Get token response if not provided.
		if (empty($token_response)) {
			$token_response = $this->get_token_response_from_storage($user_id);
		}

		// Calculate access token expiry.
		$access_token_expiry = 'N/A';
		$token_issued_at = $token_response['token_issued_at'] ?? $token_response['time'] ?? null;
		if (!empty($token_response['expires_in']) && !empty($token_issued_at)) {
			$expiration_time = intval($token_issued_at) + intval($token_response['expires_in']);
			$access_token_expiry = wp_date('Y-m-d H:i:s', $expiration_time);
		}

		// Get WordPress session expiry for the CURRENT session.
		$wp_session_expiry = 'N/A';
		$debug_info = '';
		$current_session_token = wp_get_session_token();

		if (empty($current_session_token)) {
			$debug_info = ' (no current session token)';
		} else {
			// Use WP_Session_Tokens manager API to avoid cache inconsistency with multiple sessions.
			$manager = WP_Session_Tokens::get_instance($user_id);
			$session = $manager->get($current_session_token);

			if (empty($session)) {
				$all_sessions = $manager->get_all();
				$debug_info = sprintf(' (current session not in stored sessions, %d total)', count($all_sessions));
			} else {
				$wp_session_expiry = wp_date('Y-m-d H:i:s', $session['expiration']);
			}
		}

		return sprintf(
			'[Access token expires: %s | WP session expires: %s%s]',
			$access_token_expiry,
			$wp_session_expiry,
			$debug_info
		);
	}

	/**
	 * Check if an error is a network/timeout error.
	 *
	 * Network/timeout errors should NOT result in logout since they are
	 * temporary WordPress/server issues, not authentication failures.
	 *
	 * @param string      $error_code The WordPress error code to check.
	 * @param WP_Error    $error_obj  Optional WP_Error object to check error data for HTTP status.
	 *
	 * @return bool True if this is a network/timeout error, false otherwise.
	 */
	private function is_network_timeout_error($error_code, $error_obj = null)
	{
		$network_error_codes = array(
			'http_request_failed',        // cURL connection failed
			'cURL error 28',              // Connection timeout
			'cURL error 7',               // Failed to connect
			'cURL error 6',               // Couldn't resolve host
			'cURL error 35',              // SSL/TLS connection error
		);

		// Check if error code matches any direct network error pattern.
		foreach ($network_error_codes as $network_code) {
			if (strpos($error_code, $network_code) !== false) {
				return true;
			}
		}


		if ($error_obj instanceof WP_Error) {
			$error_data = $error_obj->get_error_data();
			if (is_array($error_data) && isset($error_data['response']) && is_array($error_data['response'])) {
				$status_code = $error_data['response']['code'] ?? null;
				if ($status_code) {
					return false;
				}
			}
		}

		if (in_array($error_code, array('request_authentication_token', 'request_userinfo', 'refresh_token'), true)) {
			return true;
		}

		return false;
	}

	/**
	 * Handle retrieval and validation of refresh_token.
	 *
	 * Validates access token via userinfo endpoint periodically and refreshes
	 * if expired or invalid. This ensures WordPress session stays synchronized
	 * with OIDC token lifecycle.
	 *
	 * @return void
	 */
	public function ensure_tokens_still_fresh()
	{
		// Skip if user not logged in (no logging for anonymous users).
		if (!is_user_logged_in()) {
			return;
		}

		// Skip if token refresh is disabled in settings.
		if (!$this->settings->token_refresh_enable) {
			return;
		}

		$user_id = wp_get_current_user()->ID;
		$token = wp_get_session_token();
		if (empty($token)) {
			return;
		}

		// Read token data from database.
		$last_token_response = $this->token_storage->get_token($token);
		if (empty($last_token_response) || empty($last_token_response['access_token'])) {
			if (!empty($this->settings->disable_password_auth)) {
				$user = get_user_by('id', $user_id);
				$expiry_info = $this->get_expiry_info_for_logging($user_id, null);

				$this->logger->log(
					array(
						'type' => 'logout_no_oidc_token_when_password_disabled',
						'user_id' => $user_id,
						'username' => $user ? $user->user_login : 'unknown',
						'reason' => 'No OIDC token found in session, but password authentication is disabled. Only OIDC logins are allowed.',
						'token_state' => null,
						'expiry_info' => $expiry_info,
					),
					'logout_no_oidc_token_password_disabled',
					null
				);
				wp_logout();
			}
			return;
		}

		// Check local expiration first (free) before making any HTTP calls.
		if (!empty($last_token_response['expires_in']) && !empty($last_token_response['token_issued_at'])) {
			$expiration_time = intval($last_token_response['token_issued_at']) + intval($last_token_response['expires_in']);
			if (time() >= $expiration_time) {
				// On AJAX, skip refresh if token expired less than 30s ago; let the next page load handle it.
				if (function_exists('wp_doing_ajax') && wp_doing_ajax() && (time() - $expiration_time) < 30) {
					return;
				}
				$this->refresh_access_token($user_id);
				return;
			}
		}

		// Token is not expired locally. Periodically validate with userinfo endpoint
		// to catch server-side revocations (default: every 10 minutes).
		$last_userinfo_check = $last_token_response['last_userinfo_check'] ?? 0;
		$check_interval = !empty($this->settings->userinfo_check_interval)
			? intval($this->settings->userinfo_check_interval)
			: 10 * MINUTE_IN_SECONDS;
		$check_interval = apply_filters('openid-connect-generic-userinfo-check-interval', $check_interval);
		$time_since_last_check = time() - intval($last_userinfo_check);
		$should_validate = $time_since_last_check > $check_interval;

		if ($should_validate && !empty($this->settings->endpoint_userinfo)) {
			$userinfo_result = $this->client->request_userinfo($last_token_response['access_token']);

			if (is_wp_error($userinfo_result)) {
				$error_code = $userinfo_result->get_error_code();
				$is_network_error = $this->is_network_timeout_error($error_code, $userinfo_result);

				if ($is_network_error) {
					$this->logger->log(
						array(
							'type' => 'userinfo_network_error',
							'error' => $userinfo_result->get_error_message(),
							'code' => $error_code,
							'action' => 'session_preserved',
						),
						'ensure_tokens_still_fresh_network_error',
						null
					);
					$token_data = $last_token_response;
					$token_data['last_userinfo_check'] = time();
					$this->token_storage->save_token($token, $user_id, $token_data);
					return;
				}

				// Authentication or other error - attempt token refresh.
				$this->refresh_access_token($user_id);
				return;
			}

			// Userinfo check successful - update last_userinfo_check timestamp.
			$token_data = $last_token_response;
			$token_data['last_userinfo_check'] = time();
			$this->token_storage->save_token($token, $user_id, $token_data);
		}
	}

	/**
	 * Refresh the access token using the refresh token.
	 *
	 * Uses a stamp in the token table so only one request performs the refresh;
	 * others return immediately. No locking, sleeping, or polling.
	 *
	 * @param int $user_id The WordPress user ID.
	 *
	 * @return void
	 */
	private function refresh_access_token($user_id)
	{
		$token = wp_get_session_token();
		if (empty($token)) {
			return;
		}

		$current_token_data = $this->token_storage->get_token($token);
		if (empty($current_token_data)) {
			$user = get_user_by('id', $user_id);
			$expiry_info = $this->get_expiry_info_for_logging($user_id, null);
			$this->logger->log(
				array(
					'type' => 'logout_no_refresh_token_in_session',
					'user_id' => $user_id,
					'username' => $user ? $user->user_login : 'unknown',
					'reason' => 'No OIDC refresh token found in database',
					'token_state' => null,
					'expiry_info' => $expiry_info,
				),
				'logout_no_refresh_token',
				null
			);
			wp_logout();
			return;
		}

		$refresh_token = $current_token_data['refresh_token'] ?? null;
		if (empty($refresh_token)) {
			$user = get_user_by('id', $user_id);
			$expiry_info = $this->get_expiry_info_for_logging($user_id, $current_token_data);
			$this->logger->log(
				array(
					'type' => 'logout_empty_refresh_token',
					'user_id' => $user_id,
					'username' => $user ? $user->user_login : 'unknown',
					'reason' => 'Refresh token is empty',
					'token_state' => $current_token_data,
					'expiry_info' => $expiry_info,
				),
				'logout_empty_refresh_token',
				null
			);
			wp_logout();
			return;
		}

		if (!$this->token_storage->claim_refresh($token, 30)) {
			$this->logger->log(
				array(
					'type' => 'refresh_deferred',
					'user_id' => $user_id,
					'message' => 'Another request is refreshing token, skipping',
				),
				'refresh_access_token',
				null
			);
			return;
		}

		try {
			$token_result = $this->client->request_new_tokens($refresh_token);

			if (is_wp_error($token_result)) {
				$error_code = $token_result->get_error_code();
				$is_network_error = $this->is_network_timeout_error($error_code, $token_result);

				if ($is_network_error) {
					$this->logger->log(
						array(
							'type' => 'token_refresh_network_error',
							'error' => $token_result->get_error_message(),
							'code' => $error_code,
							'action' => 'session_preserved',
						),
						'refresh_access_token_network_error',
						null
					);
					return;
				}

				$user = get_user_by('id', $user_id);
				$expiry_info = $this->get_expiry_info_for_logging($user_id, $current_token_data);
				$this->logger->log(
					array(
						'type' => 'logout_token_refresh_http_error',
						'user_id' => $user_id,
						'username' => $user ? $user->user_login : 'unknown',
						'reason' => 'Token refresh failed with HTTP error',
						'error' => $token_result->get_error_message(),
						'code' => $error_code,
						'token_state' => $current_token_data,
						'expiry_info' => $expiry_info,
					),
					'logout_http_error',
					null
				);
				wp_logout();
				return;
			}

			$token_response = $this->client->get_token_response($token_result);
			if (is_wp_error($token_response)) {
				$error_code = $token_response->get_error_code();
				if ('http-error-401' === $error_code) {
					$refreshed_token_data = $this->token_storage->get_token($token);
					if (!empty($refreshed_token_data)) {
						$new_refresh_token = $refreshed_token_data['refresh_token'] ?? null;
						$new_token_issued_at = $refreshed_token_data['token_issued_at'] ?? 0;
						$old_token_issued_at = $current_token_data['token_issued_at'] ?? 0;
						if ($new_refresh_token !== $refresh_token || $new_token_issued_at > $old_token_issued_at) {
							$this->logger->log(
								array(
									'type' => 'refresh_race_recovered',
									'user_id' => $user_id,
									'message' => '401 during refresh but token was updated by another request',
								),
								'refresh_access_token',
								null
							);
							return;
						}
					}
				}

				$expiry_info = $this->get_expiry_info_for_logging($user_id, $current_token_data);
				$this->logger->log(
					array(
						'type' => 'logout_token_response_failed',
						'user_id' => $user_id,
						'reason' => 'Token response parsing failed during refresh',
						'error' => $token_response->get_error_message(),
						'code' => $token_response->get_error_code(),
						'token_state' => $current_token_data,
						'expiry_info' => $expiry_info,
					),
					'logout_token_response_error',
					null
				);
				wp_logout();
				return;
			}

			$token_response['time'] = time();
			$session_expiration = $this->get_wp_session_expiration_from_oidc($token_response);
			$token_data = array(
				'access_token' => $token_response['access_token'] ?? '',
				'refresh_token' => $token_response['refresh_token'] ?? null,
				'id_token' => $token_response['id_token'] ?? null,
				'expires_in' => isset($token_response['expires_in']) ? intval($token_response['expires_in']) : 0,
				'token_issued_at' => intval($token_response['time']),
				'session_expiration' => $session_expiration,
				'last_userinfo_check' => time(),
			);

			$this->token_storage->save_token($token, $user_id, $token_data);

			$manager = WP_Session_Tokens::get_instance($user_id);
			$session = $manager->get($token);
			if (!empty($session)) {
				$session['expiration'] = $session_expiration;
				$manager->update($token, $session);
				$cookie_expiration_duration = $session_expiration - time();
				$filter_callback = function ($expiration_time, $filter_user_id, $remember) use ($cookie_expiration_duration, $user_id) {
					if ($filter_user_id === $user_id) {
						return $cookie_expiration_duration;
					}
					return $expiration_time;
				};
				add_filter('auth_cookie_expiration', $filter_callback, 999, 3);
				wp_set_auth_cookie($user_id, true, '', $token);
				remove_filter('auth_cookie_expiration', $filter_callback, 999);
			}
		} finally {
			$this->token_storage->release_refresh($token);
		}
	}


	/**
	 * Get token response from database storage.
	 *
	 * @param int $user_id The user ID.
	 * @return array|null Token response array or null if not found.
	 */
	private function get_token_response_from_storage($user_id)
	{
		$token = wp_get_session_token();
		if (empty($token)) {
			return null;
		}
		return $this->token_storage->get_token($token);
	}

	/**
	 * Get the current user's token response from storage.
	 * Public method for use by integrations.
	 *
	 * @param int $user_id The user ID.
	 *
	 * @return array|null Token response array or null if not found.
	 */
	public function get_current_user_token_response($user_id)
	{
		return $this->get_token_response_from_storage($user_id);
	}

	/**
	 * Get the client instance.
	 * Public method for use by integrations.
	 *
	 * @return OpenID_Connect_Generic_Client The client instance.
	 */
	public function get_client()
	{
		return $this->client;
	}

	/**
	 * Get the logger instance.
	 *
	 * @return OpenID_Connect_Generic_Option_Logger
	 */
	public function get_logger()
	{
		return $this->logger;
	}

	/**
	 * Save OIDC token response to the database.
	 *
	 * @param string $token          The WordPress session token.
	 * @param int    $user_id        The user ID.
	 * @param array  $token_response The OIDC token response.
	 * @return void
	 */
	private function save_token_to_db($token, $user_id, $token_response)
	{
		if (empty($token) || empty($user_id)) {
			return;
		}

		$session_expiration = $this->get_wp_session_expiration_from_oidc($token_response);

		$token_data = array(
			'access_token' => $token_response['access_token'] ?? '',
			'refresh_token' => $token_response['refresh_token'] ?? null,
			'id_token' => $token_response['id_token'] ?? null,
			'expires_in' => isset($token_response['expires_in']) ? intval($token_response['expires_in']) : 0,
			'token_issued_at' => isset($token_response['time']) ? intval($token_response['time']) : time(),
			'session_expiration' => $session_expiration,
			'last_userinfo_check' => time(),
		);

		$success = $this->token_storage->save_token($token, $user_id, $token_data);
		if (!$success) {
			$this->logger->log(
				array(
					'type' => 'token_save_warning',
					'user_id' => $user_id,
					'message' => 'Failed to save tokens to database',
				),
				'save_token_to_db',
				null
			);
		}
	}


	/**
	 * Handle errors by redirecting the user to the login form along with an
	 * error code
	 *
	 * @param WP_Error $error A WordPress error object.
	 *
	 * @return void
	 */
	public function error_redirect($error)
	{
		$this->logger->log($error, null, null);

		// Redirect user back to login page.
		wp_redirect(
			wp_login_url() .
			'?login-error=' . $error->get_error_code() .
			'&message=' . urlencode($error->get_error_message())
		);
		exit;
	}

	/**
	 * Get the current error state.
	 *
	 * @return bool|WP_Error
	 */
	public function get_error()
	{
		return $this->error;
	}

	/**
	 * Add the end_session endpoint to WordPress core's whitelist of redirect hosts.
	 *
	 * @param array<string> $allowed The allowed redirect host names.
	 *
	 * @return array<string>|bool
	 */
	public function update_allowed_redirect_hosts($allowed)
	{
		$host = parse_url($this->settings->endpoint_end_session, PHP_URL_HOST);
		if (!$host) {
			return false;
		}

		$allowed[] = $host;
		return $allowed;
	}

	/**
	 * Intercept logout to redirect to IDP first before destroying WordPress session.
	 *
	 * This allows the user to confirm logout at the IDP. If confirmed, IDP redirects
	 * back with loggedout=true and then WordPress session is destroyed. If cancelled,
	 * IDP redirects to home page and user remains logged in.
	 *
	 * @return void
	 */
	public function intercept_logout_redirect()
	{
		// Check if this is a logout request.
		if (isset($_GET['action']) && 'logout' === $_GET['action']) {
			// Verify nonce for security.
			check_admin_referer('log-out');

			// Build IDP logout URL with post_logout_redirect_uri.
			$logout_return_url = home_url('?loggedout=true');
			$end_session_url = $this->settings->endpoint_end_session;

			// Get current user's ID token for logout hint.
			$id_token = $this->get_current_id_token();

			// Build logout URL with parameters.
			$query = parse_url($end_session_url, PHP_URL_QUERY);
			$end_session_url .= $query ? '&' : '?';
			$end_session_url .= sprintf(
				'id_token_hint=%s&post_logout_redirect_uri=%s',
				$id_token,
				urlencode($logout_return_url)
			);

			// Redirect to IDP without destroying WordPress session yet.
			wp_redirect($end_session_url);
			exit;
		}
	}

	/**
	 * Handle the return from IDP logout.
	 *
	 * Detects the loggedout=true parameter and destroys the WordPress session.
	 * This runs on all pages via the init hook.
	 *
	 * @return void
	 */
	public function handle_logout_return()
	{
		// Check if user is returning from IDP logout.
		if (isset($_GET['loggedout']) && 'true' === $_GET['loggedout']) {
			// User confirmed logout at IDP, now destroy WordPress session.
			if (is_user_logged_in()) {
				$user_id = wp_get_current_user()->ID;
				$user = wp_get_current_user();
				$current_token_response = $this->get_token_response_from_storage($user_id);
				$expiry_info = $this->get_expiry_info_for_logging($user_id, $current_token_response);

				$this->logger->log(
					array(
						'type' => 'logout_user_confirmed_at_idp',
						'user_id' => $user_id,
						'username' => $user->user_login,
						'reason' => 'User confirmed logout at IDP',
						'token_state' => $current_token_response,
						'expiry_info' => $expiry_info,
					),
					'logout_idp_confirmed',
					null
				);
				wp_logout();
			}
			// Redirect to homepage without the loggedout parameter to clean up the URL.
			wp_safe_redirect(home_url());
			exit;
		}
	}

	/**
	 * Clean up token from database on logout.
	 *
	 * @return void
	 */
	public function cleanup_token_on_logout()
	{
		$wp_session_token = wp_get_session_token();
		if (!empty($wp_session_token)) {
			$this->token_storage->delete_token($wp_session_token);
		}
	}

	/**
	 * Get the current user's ID token from session.
	 *
	 * @return string The ID token or empty string if not available.
	 */
	private function get_current_id_token()
	{
		if (!is_user_logged_in()) {
			return '';
		}

		$user_id = get_current_user_id();
		$token_response = $this->get_token_response_from_storage($user_id);

		if (!empty($token_response['id_token'])) {
			return $token_response['id_token'];
		}

		return '';
	}

	/**
	 * Modify outgoing requests according to settings.
	 *
	 * @param array<mixed> $request   The outgoing request array.
	 * @param string       $operation The request operation name.
	 *
	 * @return mixed
	 */
	public function alter_request($request, $operation)
	{
		if (!empty($this->settings->http_request_timeout)) {
			$request['timeout'] = intval($this->settings->http_request_timeout);
		}

		if ($this->settings->no_sslverify) {
			$request['sslverify'] = false;
		}

		return $request;
	}

	/**
	 * Control the authentication and subsequent authorization of the user when
	 * returning from the IDP.
	 *
	 * @return void
	 */
	public function authentication_request_callback()
	{
		$client = $this->client;

		// Start the authentication flow.
		$authentication_request = $client->validate_authentication_request($_GET);

		if (is_wp_error($authentication_request)) {
			$this->error_redirect($authentication_request);
		}

		// Retrieve the authentication code from the authentication request.
		$code = $client->get_authentication_code($authentication_request);

		if (is_wp_error($code)) {
			$this->error_redirect($code);
		}

		// Retrieve the authentication state from the authentication request.
		$state = $client->get_authentication_state($authentication_request);

		if (is_wp_error($state)) {
			$this->error_redirect($state);
		}

		// Attempting to exchange an authorization code for an authentication token.
		$token_result = $client->request_authentication_token($code);

		if (is_wp_error($token_result)) {
			$this->error_redirect($token_result);
		}

		// Get the decoded response from the authentication request result.
		$token_response = $client->get_token_response($token_result);

		// Allow for other plugins to alter data before validation.
		$token_response = apply_filters('openid-connect-modify-token-response-before-validation', $token_response);

		if (is_wp_error($token_response)) {
			$this->error_redirect($token_response);
		}

		// Ensure the that response contains required information.
		$valid = $client->validate_token_response($token_response);

		if (is_wp_error($valid)) {
			$this->error_redirect($valid);
		}

		/**
		 * The id_token is used to identify the authenticated user, e.g. for SSO.
		 * The access_token must be used to prove access rights to protected
		 * resources e.g. for the userinfo endpoint
		 */
		$id_token_claim = $client->get_id_token_claim($token_response);

		// Allow for other plugins to alter data before validation.
		$id_token_claim = apply_filters('openid-connect-modify-id-token-claim-before-validation', $id_token_claim);

		if (is_wp_error($id_token_claim)) {
			$this->error_redirect($id_token_claim);
		}

		// Validate our id_token has required values.
		$valid = $client->validate_id_token_claim($id_token_claim);

		if (is_wp_error($valid)) {
			$this->error_redirect($valid);
		}

		// If userinfo endpoint is set, exchange the token_response for a user_claim.
		if (!empty($this->settings->endpoint_userinfo) && isset($token_response['access_token'])) {
			$user_claim = $client->get_user_claim($token_response);
		} else {
			$user_claim = $id_token_claim;
		}

		if (is_wp_error($user_claim)) {
			$this->error_redirect($user_claim);
		}

		// Validate our user_claim has required values.
		$valid = $client->validate_user_claim($user_claim, $id_token_claim);

		if (is_wp_error($valid)) {
			$this->error_redirect($valid);
		}

		/**
		 * End authorization
		 * -
		 * Request is authenticated and authorized - start user handling
		 */
		$subject_identity = $client->get_subject_identity($id_token_claim);
		$user = $this->get_user_by_identity($subject_identity);

		// A pre-existing IDP mapped user wasn't found.
		if (!$user) {
			// If linking existing users or creating new ones call the `create_new_user` method which handles both cases.
			if ($this->settings->link_existing_users || $this->settings->create_if_does_not_exist) {
				$user = $this->create_new_user($subject_identity, $user_claim);
				if (is_wp_error($user)) {
					$this->error_redirect($user);
				}
			} else {
				$this->error_redirect(new WP_Error('identity-not-map-existing-user', __('User identity is not linked to an existing WordPress user.', 'daggerhart-openid-connect-generic'), $user_claim));
			}
		}

		// Validate the found / created user.
		$valid = $this->validate_user($user);

		if (is_wp_error($valid)) {
			$this->error_redirect($valid);
		}

		// Login the found / created user.
		$start_time = microtime(true);
		$this->login_user($user, $token_response, $id_token_claim, $user_claim, $subject_identity);
		$end_time = microtime(true);
		// Log our success.
		$this->logger->log("Successful login for: {$user->user_login} ({$user->ID})", 'login-success', $end_time - $start_time);

		// Allow plugins / themes to take action once a user is logged in.
		$start_time = microtime(true);
		do_action('openid-connect-generic-user-logged-in', $user);
		$end_time = microtime(true);
		$this->logger->log('openid-connect-generic-user-logged-in', 'do_action', $end_time - $start_time);

		// Default redirect to the homepage.
		$redirect_url = home_url();
		// Redirect user according to redirect set in state.
		$state_object = get_transient('openid-connect-generic-state--' . $state);
		// Get the redirect URL stored with the corresponding authentication request state.
		if (!empty($state_object) && !empty($state_object[$state]) && !empty($state_object[$state]['redirect_to'])) {
			$redirect_url = $state_object[$state]['redirect_to'];
		}

		// Provide backwards compatibility for customization using the deprecated cookie method.
		if (!empty($_COOKIE[self::COOKIE_REDIRECT_KEY])) {
			$redirect_url = esc_url_raw(wp_unslash($_COOKIE[self::COOKIE_REDIRECT_KEY]));
		}

		// Only do redirect-user-back action hook when the plugin is configured for it.
		if ($this->settings->redirect_user_back) {
			do_action('openid-connect-generic-redirect-user-back', $redirect_url, $user);
		}

		wp_redirect($redirect_url);

		exit;
	}

	/**
	 * Validate the potential WP_User.
	 *
	 * @param WP_User|WP_Error|false $user The user object.
	 *
	 * @return true|WP_Error
	 */
	public function validate_user($user)
	{
		// Ensure the found user is a real WP_User.
		if (!is_a($user, 'WP_User') || !$user->exists()) {
			return new WP_Error('invalid-user', __('Invalid user.', 'daggerhart-openid-connect-generic'), $user);
		}

		return true;
	}

	/**
	 * Refresh user claim.
	 *
	 * @param WP_User $user             The user object.
	 * @param array   $token_response   The token response.
	 *
	 * @return WP_Error|array
	 */
	public function refresh_user_claim($user, $token_response)
	{
		$client = $this->client;

		/**
		 * The id_token is used to identify the authenticated user, e.g. for SSO.
		 * The access_token must be used to prove access rights to protected
		 * resources e.g. for the userinfo endpoint
		 */
		$id_token_claim = $client->get_id_token_claim($token_response);

		// Allow for other plugins to alter data before validation.
		$id_token_claim = apply_filters('openid-connect-modify-id-token-claim-before-validation', $id_token_claim);

		if (is_wp_error($id_token_claim)) {
			return $id_token_claim;
		}

		// Validate our id_token has required values.
		$valid = $client->validate_id_token_claim($id_token_claim);

		if (is_wp_error($valid)) {
			return $valid;
		}

		// If userinfo endpoint is set, exchange the token_response for a user_claim.
		if (!empty($this->settings->endpoint_userinfo) && isset($token_response['access_token'])) {
			$user_claim = $client->get_user_claim($token_response);
		} else {
			$user_claim = $id_token_claim;
		}

		if (is_wp_error($user_claim)) {
			return $user_claim;
		}

		// Validate our user_claim has required values.
		$valid = $client->validate_user_claim($user_claim, $id_token_claim);

		if (is_wp_error($valid)) {
			$this->error_redirect($valid);
			return $valid;
		}

		// Capture the time so that access token expiration can be calculated later.
		$token_response['time'] = time();

		// Store the tokens in database.
		$this->save_token_to_db(wp_get_session_token(), $user->ID, $token_response);
		update_user_meta($user->ID, 'openid-connect-generic-last-id-token-claim', $id_token_claim);
		update_user_meta($user->ID, 'openid-connect-generic-last-user-claim', $user_claim);

		return $user_claim;
	}

	/**
	 * Record user meta data, and provide an authorization cookie.
	 *
	 * @param WP_User $user             The user object.
	 * @param array   $token_response   The token response.
	 * @param array   $id_token_claim   The ID token claim.
	 * @param array   $user_claim       The authenticated user claim.
	 * @param string  $subject_identity The subject identity from the IDP.
	 *
	 * @return void
	 */
	public function login_user($user, $token_response, $id_token_claim, $user_claim, $subject_identity): void
	{
		// Capture the time so that access token expiration can be calculated later.
		$token_response['time'] = time();

		update_user_meta($user->ID, 'openid-connect-generic-last-id-token-claim', $id_token_claim);
		update_user_meta($user->ID, 'openid-connect-generic-last-user-claim', $user_claim);

		// Assign role based on OIDC claim if role mapping is enabled.
		$this->assign_user_role_from_claim($user, $user_claim);

		// Allow plugins / themes to take action using current claims on existing user (e.g. update role).
		do_action('openid-connect-generic-update-user-using-current-claim', $user, $user_claim);

		// OIDC sessions always use persistent cookies (remember_me = true) to survive browser closes.
		// This ties WordPress session lifetime to OIDC token lifecycle.
		$remember_me = apply_filters('openid-connect-generic-remember-me', true, $user, $token_response, $id_token_claim, $user_claim, $subject_identity);

		// Calculate session expiration based on OIDC token lifetime instead of fixed days.
		$expiration = $this->get_wp_session_expiration_from_oidc($token_response);


		// Log session and token expiration details.
		$access_token_expires_in = !empty($token_response['expires_in']) ? intval($token_response['expires_in']) : 0;
		$access_token_expires_at = $access_token_expires_in > 0 ? wp_date('Y-m-d H:i:s', time() + $access_token_expires_in) : 'N/A';
		$session_expires_at = wp_date('Y-m-d H:i:s', $expiration);
		$this->logger->log(
			sprintf(
				'User %s (%d) logged in. [Access token expires: %s (%d sec) | WP session expires: %s]',
				$user->user_login,
				$user->ID,
				$access_token_expires_at,
				$access_token_expires_in,
				$session_expires_at
			),
			'login_user',
			null
		);

		$manager = WP_Session_Tokens::get_instance($user->ID);
		$token = $manager->create($expiration);

		// Save OIDC tokens to database.
		$this->save_token_to_db($token, $user->ID, $token_response);


		$cookie_expiration_duration = $expiration - time();
		$filter_callback = function ($expiration_time, $filter_user_id, $remember) use ($cookie_expiration_duration, $user) {
			if ($filter_user_id === $user->ID) {
				return $cookie_expiration_duration;
			}
			return $expiration_time;
		};
		add_filter('auth_cookie_expiration', $filter_callback, 999, 3);

		wp_set_auth_cookie($user->ID, true, '', $token);

		remove_filter('auth_cookie_expiration', $filter_callback, 999);
		do_action('wp_login', $user->user_login, $user);
	}

	/**
	 * Calculate WordPress session expiration based on OIDC token lifetime.
	 *
	 * WordPress session should last as long as the refresh token is valid,
	 * NOT as long as the access token. This allows transparent token refresh
	 * to occur while the user's session remains active.
	 *
	 * @param array $token_response The OIDC token response containing expires_in.
	 *
	 * @return int Unix timestamp for session expiration.
	 */
	private function get_wp_session_expiration_from_oidc($token_response)
	{
		// If IDP returns refresh token expiration, use that.
		if (!empty($token_response['refresh_expires_in'])) {
			return time() + intval($token_response['refresh_expires_in']);
		}

		// Use a configurable session lifetime (default 1 days).
		// This should match your refresh token lifetime or desired maximum session duration.
		$session_lifetime = apply_filters(
			'openid-connect-generic-session-lifetime',
			7 * DAY_IN_SECONDS
		);

		return time() + $session_lifetime;
	}

	/**
	 * Get the user that has meta data matching a
	 *
	 * @param string $subject_identity The IDP identity of the user.
	 *
	 * @return false|WP_User
	 */
	public function get_user_by_identity($subject_identity)
	{
		// Look for user by their openid-connect-generic-subject-identity value.
		$user_query = new WP_User_Query(
			array(
				'meta_query' => array(
					array(
						'key' => 'openid-connect-generic-subject-identity',
						'value' => $subject_identity,
					),
				),
				// Override the default blog_id (get_current_blog_id) to find users on different sites of a multisite install.
				'blog_id' => 0,
			)
		);

		// If we found existing users, grab the first one returned.
		if ($user_query->get_total() > 0) {
			$users = $user_query->get_results();
			return $users[0];
		}

		return false;
	}

	/**
	 * Avoid user_login collisions by incrementing.
	 *
	 * @param array $user_claim The IDP authenticated user claim data.
	 *
	 * @return string|WP_Error
	 */
	private function get_username_from_claim($user_claim)
	{

		// @var string $desired_username
		$desired_username = '';

		// Allow settings to take first stab at username.
		if (!empty($this->settings->identity_key) && isset($user_claim[$this->settings->identity_key])) {
			$desired_username = $user_claim[$this->settings->identity_key];
		}
		if (empty($desired_username) && isset($user_claim['preferred_username']) && !empty($user_claim['preferred_username'])) {
			$desired_username = $user_claim['preferred_username'];
		}
		if (empty($desired_username) && isset($user_claim['name']) && !empty($user_claim['name'])) {
			$desired_username = $user_claim['name'];
		}
		if (empty($desired_username) && isset($user_claim['email']) && !empty($user_claim['email'])) {
			$tmp = explode('@', $user_claim['email']);
			$desired_username = $tmp[0];
		}
		if (empty($desired_username)) {
			// Nothing to build a name from.
			return new WP_Error('no-username', __('No appropriate username found.', 'daggerhart-openid-connect-generic'), $user_claim);
		}

		// Don't use the full email address for a username.
		$_desired_username = explode('@', $desired_username);
		$desired_username = $_desired_username[0];
		// Use WordPress Core to sanitize the IDP username.
		$sanitized_username = sanitize_user($desired_username, true);
		if (empty($sanitized_username)) {
			// translators: %1$s is the santitized version of the username from the IDP.
			return new WP_Error('username-sanitization-failed', sprintf(__('Username %1$s could not be sanitized.', 'daggerhart-openid-connect-generic'), $desired_username), $desired_username);
		}

		return $sanitized_username;
	}

	/**
	 * Get a nickname.
	 *
	 * @param array $user_claim The IDP authenticated user claim data.
	 *
	 * @return string|WP_Error|null
	 */
	private function get_nickname_from_claim($user_claim)
	{
		$desired_nickname = null;
		// Allow settings to take first stab at nickname.
		if (!empty($this->settings->nickname_key) && isset($user_claim[$this->settings->nickname_key])) {
			$desired_nickname = $user_claim[$this->settings->nickname_key];
		}

		if (empty($desired_nickname)) {
			// translators: %1$s is the configured User Claim nickname key.
			return new WP_Error('no-nickname', sprintf(__('No nickname found in user claim using key: %1$s.', 'daggerhart-openid-connect-generic'), $this->settings->nickname_key), $this->settings->nickname_key);
		}

		return $desired_nickname;
	}

	/**
	 * Checks if $claimname is in the body or _claim_names of the userinfo.
	 * If yes, returns the claim value. Otherwise, returns false.
	 *
	 * @param string $claimname the claim name to look for.
	 * @param array  $userinfo the JSON to look in.
	 * @param string $claimvalue the source claim value ( from the body of the JWT of the claim source).
	 * @return true|false
	 */
	private function get_claim($claimname, $userinfo, &$claimvalue)
	{
		/**
		 * If we find a simple claim, return it.
		 */
		if (array_key_exists($claimname, $userinfo)) {
			$claimvalue = $userinfo[$claimname];
			return true;
		}
		/**
		 * If there are no aggregated claims, it is over.
		 */
		if (
			!array_key_exists('_claim_names', $userinfo) ||
			!array_key_exists('_claim_sources', $userinfo)
		) {
			return false;
		}
		$claim_src_ptr = $userinfo['_claim_names'];
		if (!isset($claim_src_ptr)) {
			return false;
		}
		/**
		 * No reference found
		 */
		if (!array_key_exists($claimname, $claim_src_ptr)) {
			return false;
		}
		$src_name = $claim_src_ptr[$claimname];
		// Reference found, but no corresponding JWT. This is a malformed userinfo.
		if (!array_key_exists($src_name, $userinfo['_claim_sources'])) {
			return false;
		}
		$src = $userinfo['_claim_sources'][$src_name];
		// Source claim is not a JWT. Abort.
		if (!array_key_exists('JWT', $src)) {
			return false;
		}
		/**
		 * Extract claim from JWT.
		 * FIXME: We probably want to verify the JWT signature/issuer here.
		 * For example, using JWKS if applicable. For symmetrically signed
		 * JWTs (HMAC), we need a way to specify the acceptable secrets
		 * and each possible issuer in the config.
		 */
		$jwt = $src['JWT'];
		list($header, $body, $rest) = explode('.', $jwt, 3);
		$body_str = base64_decode($body, false);
		if (!$body_str) {
			return false;
		}
		$body_json = json_decode($body_str, true);
		if (!isset($body_json)) {
			return false;
		}
		if (!array_key_exists($claimname, $body_json)) {
			return false;
		}
		$claimvalue = $body_json[$claimname];
		return true;
	}


	/**
	 * Build a string from the user claim according to the specified format.
	 *
	 * @param string $format               The format format of the user identity.
	 * @param array  $user_claim           The authorized user claim.
	 * @param bool   $error_on_missing_key Whether to return and error on a missing key.
	 *
	 * @return string|WP_Error
	 */
	private function format_string_with_claim($format, $user_claim, $error_on_missing_key = false)
	{
		$matches = null;
		$string = '';
		$info = '';
		$i = 0;
		if (preg_match_all('/\{[^}]*\}/u', $format, $matches, PREG_OFFSET_CAPTURE)) {
			foreach ($matches[0] as $match) {
				$key = substr($match[0], 1, -1);
				$string .= substr($format, $i, $match[1] - $i);
				if (!$this->get_claim($key, $user_claim, $info)) {
					if ($error_on_missing_key) {
						return new WP_Error(
							'incomplete-user-claim',
							__('User claim incomplete.', 'daggerhart-openid-connect-generic'),
							array(
								'message' => 'Unable to find key: ' . $key . ' in user_claim',
								'hint' => 'Verify OpenID Scope includes a scope with the attributes you need',
								'user_claim' => $user_claim,
								'format' => $format,
							)
						);
					}
				} else {
					$string .= $info;
				}
				$i = $match[1] + strlen($match[0]);
			}
		}
		$string .= substr($format, $i);
		return $string;
	}

	/**
	 * Get a displayname.
	 *
	 * @param array $user_claim           The authorized user claim.
	 * @param bool  $error_on_missing_key Whether to return and error on a missing key.
	 *
	 * @return string|null|WP_Error
	 */
	private function get_displayname_from_claim($user_claim, $error_on_missing_key = false)
	{
		if (!empty($this->settings->displayname_format)) {
			return $this->format_string_with_claim($this->settings->displayname_format, $user_claim, $error_on_missing_key);
		}
		return null;
	}

	/**
	 * Get an email.
	 *
	 * @param array $user_claim           The authorized user claim.
	 * @param bool  $error_on_missing_key Whether to return and error on a missing key.
	 *
	 * @return string|null|WP_Error
	 */
	private function get_email_from_claim($user_claim, $error_on_missing_key = false)
	{
		if (!empty($this->settings->email_format)) {
			return $this->format_string_with_claim($this->settings->email_format, $user_claim, $error_on_missing_key);
		}
		return null;
	}

	/**
	 * Create a new user from details in a user_claim.
	 *
	 * @param string $subject_identity The authenticated user's identity with the IDP.
	 * @param array  $user_claim       The authorized user claim.
	 *
	 * @return \WP_Error | \WP_User
	 */
	public function create_new_user($subject_identity, $user_claim)
	{
		$start_time = microtime(true);
		$user_claim = apply_filters('openid-connect-generic-alter-user-claim', $user_claim);

		// Default username & email to the subject identity.
		$username = $subject_identity;
		$email = $subject_identity;
		$nickname = $subject_identity;
		$displayname = $subject_identity;
		$values_missing = false;

		// Allow claim details to determine username, email, nickname and displayname.
		$_email = $this->get_email_from_claim($user_claim, true);
		if (is_wp_error($_email) || empty($_email)) {
			$values_missing = true;
		} else {
			$email = $_email;
		}

		$_username = $this->get_username_from_claim($user_claim);
		if (is_wp_error($_username) || empty($_username)) {
			$values_missing = true;
		} else {
			$username = $_username;
		}

		$_nickname = $this->get_nickname_from_claim($user_claim);
		if (is_wp_error($_nickname) || empty($_nickname)) {
			$values_missing = true;
		} else {
			$nickname = $_nickname;
		}

		$_displayname = $this->get_displayname_from_claim($user_claim, true);
		if (is_wp_error($_displayname) || empty($_displayname)) {
			$values_missing = true;
		} else {
			$displayname = $_displayname;
		}

		// Attempt another request for userinfo if some values are missing.
		if ($values_missing && isset($user_claim['access_token']) && !empty($this->settings->endpoint_userinfo)) {
			$user_claim_result = $this->client->request_userinfo($user_claim['access_token']);

			// Make sure we didn't get an error.
			if (is_wp_error($user_claim_result)) {
				return new WP_Error('bad-user-claim-result', __('Bad user claim result.', 'daggerhart-openid-connect-generic'), $user_claim_result);
			}

			$user_claim = json_decode($user_claim_result['body'], true);
		}

		$_email = $this->get_email_from_claim($user_claim, true);
		if (is_wp_error($_email)) {
			return $_email;
		}
		// Use the email address from the latest userinfo request if not empty.
		if (!empty($_email)) {
			$email = $_email;
		}

		$_username = $this->get_username_from_claim($user_claim);
		if (is_wp_error($_username)) {
			return $_username;
		}
		// Use the username from the latest userinfo request if not empty.
		if (!empty($_username)) {
			$username = $_username;
		}

		$_nickname = $this->get_nickname_from_claim($user_claim);
		if (is_wp_error($_nickname)) {
			return $_nickname;
		}
		// Use the username as the nickname if the userinfo request nickname is empty.
		if (empty($_nickname)) {
			$nickname = $username;
		}

		$_displayname = $this->get_displayname_from_claim($user_claim, true);
		if (is_wp_error($_displayname)) {
			return $_displayname;
		}
		// Use the nickname as the displayname if the userinfo request displayname is empty.
		if (empty($_displayname)) {
			$displayname = $nickname;
		}

		// Before trying to create the user, first check if a matching user exists.
		if ($this->settings->link_existing_users) {
			$uid = null;
			if ($this->settings->identify_with_username) {
				$uid = username_exists($username);
			} else {
				$uid = email_exists($email);
			}
			if (!empty($uid)) {
				$user = $this->update_existing_user($uid, $subject_identity);
				do_action('openid-connect-generic-update-user-using-current-claim', $user, $user_claim);
				$end_time = microtime(true);
				$this->logger->log("Existing user updated: {$user->user_login} ($uid)", __METHOD__, $end_time - $start_time);
				return $user;
			}
		}

		/**
		 * Allow other plugins / themes to determine authorization of new accounts
		 * based on the returned user claim.
		 */
		$create_user = apply_filters('openid-connect-generic-user-creation-test', $this->settings->create_if_does_not_exist, $user_claim);

		if (!$create_user) {
			return new WP_Error('cannot-authorize', __('Can not authorize.', 'daggerhart-openid-connect-generic'), $create_user);
		}

		// Copy the username for incrementing.
		$_username = $username;
		// Ensure prevention of linking usernames & collisions by incrementing the username if it exists.
		// @example Original user gets "name", second user gets "name2", etc.
		$count = 1;
		while (username_exists($username)) {
			$count++;
			$username = $_username . $count;
		}

		$user_data = array(
			'user_login' => $username,
			'user_pass' => wp_generate_password(32, true, true),
			'user_email' => $email,
			'display_name' => $displayname,
			'nickname' => $nickname,
			'first_name' => isset($user_claim['given_name']) ? $user_claim['given_name'] : '',
			'last_name' => isset($user_claim['family_name']) ? $user_claim['family_name'] : '',
		);
		$user_data = apply_filters('openid-connect-generic-alter-user-data', $user_data, $user_claim);

		// Create the new user.
		$uid = wp_insert_user($user_data);

		// Make sure we didn't fail in creating the user.
		if (is_wp_error($uid)) {
			return new WP_Error('failed-user-creation', __('Failed user creation.', 'daggerhart-openid-connect-generic'), $uid);
		}

		// Retrieve our new user.
		$user = get_user_by('id', $uid);

		// Save some meta data about this new user for the future.
		add_user_meta($user->ID, 'openid-connect-generic-subject-identity', (string) $subject_identity, true);

		// Assign role based on OIDC claim if role mapping is enabled.
		$this->assign_user_role_from_claim($user, $user_claim);

		// Log the results.
		$end_time = microtime(true);
		$this->logger->log("New user created: {$user->user_login} ($uid)", __METHOD__, $end_time - $start_time);

		// Allow plugins / themes to take action on new user creation.
		do_action('openid-connect-generic-user-create', $user, $user_claim);

		return $user;
	}

	/**
	 * Update an existing user with OpenID Connect meta data
	 *
	 * @param int    $uid              The WordPress User ID.
	 * @param string $subject_identity The subject identity from the IDP.
	 *
	 * @return WP_Error|WP_User
	 */
	public function update_existing_user($uid, $subject_identity)
	{
		// Add the OpenID Connect meta data.
		update_user_meta($uid, 'openid-connect-generic-subject-identity', strval($subject_identity));

		// Allow plugins / themes to take action on user update.
		do_action('openid-connect-generic-user-update', $uid);

		// Return our updated user.
		return get_user_by('id', $uid);
	}

	/**
	 * Assign WordPress role to user based on OIDC claim values.
	 *
	 * @param WP_User $user       The WordPress user object.
	 * @param array   $user_claim The authenticated user claim from OIDC.
	 *
	 * @return void
	 */
	private function assign_user_role_from_claim($user, $user_claim)
	{
		// Check if role mapping is enabled.
		if (empty($this->settings->enable_role_mapping)) {
			return;
		}

		$role_claim_key = $this->settings->role_claim_key;
		$role_mappings = $this->settings->role_mappings;
		$default_role = $this->settings->default_role;

		// Ensure we have a default role.
		if (empty($default_role)) {
			$default_role = 'subscriber';
		}

		// Check if the claim key exists in the user claim.
		if (empty($role_claim_key) || !isset($user_claim[$role_claim_key])) {
			// No claim key or claim doesn't exist, use default role.
			$user->set_role($default_role);
			return;
		}

		// Get the claim value(s).
		$claim_value = $user_claim[$role_claim_key];

		// Normalize to array - handle both single value and array formats.
		if (!is_array($claim_value)) {
			$claim_values = array($claim_value);
		} else {
			$claim_values = $claim_value;
		}

		// Use the first value from the array.
		$first_claim_value = !empty($claim_values) ? $claim_values[0] : '';

		// If no claim value, use default role.
		if (empty($first_claim_value)) {
			$user->set_role($default_role);
			return;
		}

		// Try to find a matching role mapping.
		$matched_role = null;
		if (!empty($role_mappings) && is_array($role_mappings)) {
			foreach ($role_mappings as $mapping) {
				if (isset($mapping['claim_value']) && isset($mapping['wp_role'])) {
					// Exact match (case-sensitive).
					if ($mapping['claim_value'] === $first_claim_value) {
						$matched_role = $mapping['wp_role'];
						break;
					}
				}
			}
		}

		// Set the role - either matched or default.
		if ($matched_role) {
			$user->set_role($matched_role);
		} else {
			$user->set_role($default_role);
		}
	}
}
