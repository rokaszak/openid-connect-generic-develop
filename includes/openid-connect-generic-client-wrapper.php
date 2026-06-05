<?php

class OpenID_Connect_Generic_Client_Wrapper
{


	const COOKIE_REDIRECT_KEY = 'openid-connect-generic-redirect';


	private $client;


	private $settings;


	private $logger;


	private $token_storage;


	private $error = false;


	public function __construct(OpenID_Connect_Generic_Client $client, OpenID_Connect_Generic_Option_Settings $settings, OpenID_Connect_Generic_Option_Logger $logger)
	{
		$this->client = $client;
		$this->settings = $settings;
		$this->logger = $logger;
		$this->token_storage = new OpenID_Connect_Generic_Token_Storage($logger);
	}


	public static function register(OpenID_Connect_Generic_Client $client, OpenID_Connect_Generic_Option_Settings $settings, OpenID_Connect_Generic_Option_Logger $logger)
	{
		$client_wrapper = new self($client, $settings, $logger);


		add_action('wp_loaded', array($client_wrapper, 'ensure_tokens_still_fresh'), 1);


		add_action('wp_logout', array($client_wrapper, 'cleanup_token_on_logout'), 10);


		if ($settings->endpoint_end_session) {
			add_action('login_init', array($client_wrapper, 'intercept_logout_redirect'), 1);
			add_action('wp_ajax_oidc_logout', array($client_wrapper, 'ajax_logout'));
			add_action('wp_footer', array($client_wrapper, 'print_logout_script'));
			add_action('admin_footer', array($client_wrapper, 'print_logout_script'));
		}


		add_filter('openid-connect-generic-alter-request', array($client_wrapper, 'alter_request'), 10, 2);

		if (is_admin()) {

			add_action('wp_ajax_openid-connect-authorize', array($client_wrapper, 'authentication_request_callback'));
			add_action('wp_ajax_nopriv_openid-connect-authorize', array($client_wrapper, 'authentication_request_callback'));
		}

		if ($settings->alternate_redirect_uri) {

			add_rewrite_rule('^openid-connect-authorize/?', 'index.php?openid-connect-authorize=1', 'top');
			add_rewrite_tag('%openid-connect-authorize%', '1');
			add_action('parse_request', array($client_wrapper, 'alternate_redirect_uri_parse_request'));
		}

		return $client_wrapper;
	}


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


	public function get_redirect_to()
	{

		global $wp;

		if (isset($GLOBALS['pagenow']) && 'wp-login.php' == $GLOBALS['pagenow'] && isset($_GET['action']) && 'logout' === $_GET['action']) {
			return '';
		}


		$redirect_url = home_url();


		if (isset($GLOBALS['pagenow']) && 'wp-login.php' == $GLOBALS['pagenow']) {
			$redirect_url = admin_url();
		}


		if (isset($_REQUEST['redirect_to'])) {
			$redirect_url = esc_url_raw(wp_unslash($_REQUEST['redirect_to']));
		}


		if ($this->settings->redirect_user_back) {
			if (!empty($wp->query_string)) {
				$redirect_url = home_url('?' . $wp->query_string);
			}
			if (!empty($wp->request)) {
				$redirect_url = home_url(add_query_arg(null, null));

				if ($wp->did_permalink) {
					$redirect_url = home_url(add_query_arg($_GET, trailingslashit($wp->request)));
				}
			}
		}


		$redirect_url = apply_filters_deprecated(
			'openid-connect-generic-cookie-redirect-url',
			array($redirect_url),
			'3.8.2',
			'openid-connect-generic-client-redirect-to'
		);


		return apply_filters('openid-connect-generic-client-redirect-to', $redirect_url);
	}


	public function get_authentication_url($atts = array())
	{

		if (!empty($this->settings->discovery_failed) && !empty($this->settings->failure_redirect_url)) {
			return $this->settings->failure_redirect_url;
		}

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


	private function get_expiry_info_for_logging($user_id, $token_response = null)
	{

		if (empty($token_response)) {
			$token_response = $this->get_token_response_from_storage($user_id);
		}


		$access_token_expiry = 'N/A';
		$token_issued_at = $token_response['token_issued_at'] ?? $token_response['time'] ?? null;
		if (!empty($token_response['expires_in']) && !empty($token_issued_at)) {
			$expiration_time = intval($token_issued_at) + intval($token_response['expires_in']);
			$access_token_expiry = wp_date('Y-m-d H:i:s', $expiration_time);
		}


		$wp_session_expiry = 'N/A';
		$debug_info = '';
		$current_session_token = wp_get_session_token();

		if (empty($current_session_token)) {
			$debug_info = ' (no current session token)';
		} else {

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


	private function is_network_timeout_error($error_code, $error_obj = null)
	{
		$network_error_codes = array(
			'http_request_failed',
			'cURL error 28',
			'cURL error 7',
			'cURL error 6',
			'cURL error 35',
		);


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


	public function ensure_tokens_still_fresh()
	{

		if (!is_user_logged_in()) {
			return;
		}


		if (!$this->settings->token_refresh_enable) {
			return;
		}

		$user_id = wp_get_current_user()->ID;
		$token = wp_get_session_token();
		if (empty($token)) {
			return;
		}


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


		if (!empty($last_token_response['expires_in']) && !empty($last_token_response['token_issued_at'])) {
			$expiration_time = intval($last_token_response['token_issued_at']) + intval($last_token_response['expires_in']);
			if (time() >= $expiration_time) {

				if (function_exists('wp_doing_ajax') && wp_doing_ajax() && (time() - $expiration_time) < 30) {
					return;
				}
				$this->refresh_access_token($user_id);
				return;
			}
		}



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


				$this->refresh_access_token($user_id);
				return;
			}


			$token_data = $last_token_response;
			$token_data['last_userinfo_check'] = time();
			$this->token_storage->save_token($token, $user_id, $token_data);


			if (!is_wp_error($userinfo_result) && isset($userinfo_result['body'])) {
				$fresh_claim = json_decode($userinfo_result['body'], true);
				if (is_array($fresh_claim)) {
					$user = get_user_by('id', $user_id);
					if ($user) {
						$this->assign_user_role_from_claim($user, $fresh_claim);
						$this->sync_user_meta_from_claims($user, $fresh_claim);
						update_user_meta($user->ID, 'openid-connect-generic-last-user-claim', $fresh_claim);
					}
				}
			}
		}
	}


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


	private function get_token_response_from_storage($user_id)
	{
		$token = wp_get_session_token();
		if (empty($token)) {
			return null;
		}
		return $this->token_storage->get_token($token);
	}


	public function get_current_user_token_response($user_id)
	{
		return $this->get_token_response_from_storage($user_id);
	}


	public function get_client()
	{
		return $this->client;
	}


	public function get_logger()
	{
		return $this->logger;
	}


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


	public function error_redirect($error)
	{
		$this->logger->log($error, null, null);


		wp_redirect(
			wp_login_url() .
			'?login-error=' . $error->get_error_code() .
			'&message=' . urlencode($error->get_error_message())
		);
		exit;
	}


	public function get_error()
	{
		return $this->error;
	}


	public function intercept_logout_redirect()
	{
		if (!isset($_GET['action']) || 'logout' !== $_GET['action']) {
			return;
		}

		check_admin_referer('log-out');


		$id_token = $this->get_current_id_token();
		$user_id = get_current_user_id();
		$user = wp_get_current_user();

		$this->logger->log(
			array(
				'type' => 'logout_initiated',
				'user_id' => $user_id,
				'username' => $user->user_login,
				'has_id_token' => !empty($id_token),
			),
			'logout',
			null
		);



		$this->notify_idp_logout($id_token);


		wp_logout();


		wp_safe_redirect(home_url());
		exit;
	}


	public function ajax_logout()
	{
		check_ajax_referer('oidc-logout', 'nonce');

		if (!is_user_logged_in()) {
			wp_send_json_success(array('redirect_url' => home_url()));
			return;
		}


		$id_token = $this->get_current_id_token();
		$user_id = get_current_user_id();
		$user = wp_get_current_user();

		$this->logger->log(
			array(
				'type' => 'logout_initiated',
				'user_id' => $user_id,
				'username' => $user->user_login,
				'has_id_token' => !empty($id_token),
				'source' => 'ajax',
			),
			'logout',
			null
		);


		$this->notify_idp_logout($id_token);


		wp_logout();


		wp_send_json_success(array('redirect_url' => home_url()));
	}


	private function notify_idp_logout($id_token)
	{
		$end_session_url = $this->settings->endpoint_end_session;

		if (empty($end_session_url) || empty($id_token)) {
			$this->logger->log(
				array(
					'type' => 'logout_idp_skipped',
					'reason' => empty($end_session_url) ? 'no endpoint configured' : 'no id_token available',
				),
				'logout',
				null
			);
			return;
		}

		$response = wp_remote_post(
			$end_session_url,
			array(
				'timeout' => 5,
				'body' => array(
					'id_token_hint' => $id_token,
				),
				'sslverify' => !$this->settings->no_sslverify,
			)
		);

		if (is_wp_error($response)) {
			$this->logger->log(
				array(
					'type' => 'logout_idp_error',
					'error' => $response->get_error_message(),
				),
				'logout',
				null
			);
			return;
		}

		$response_code = wp_remote_retrieve_response_code($response);
		$response_body = wp_remote_retrieve_body($response);

		$this->logger->log(
			array(
				'type' => 'logout_idp_notified',
				'response_code' => $response_code,
				'response_body' => $response_body,
			),
			'logout',
			null
		);
	}


	public function print_logout_script()
	{
		if (!is_user_logged_in() || empty($this->settings->endpoint_end_session)) {
			return;
		}

		$ajax_url = esc_url(admin_url('admin-ajax.php'));
		$nonce = wp_create_nonce('oidc-logout');
		$home_url = esc_url(home_url());
		?>
		<script>
		(function(){
			var busy=false;
			function go(){
				if(busy)return;busy=true;
				var o=document.createElement('div');
				o.id='oidc-lo';
				o.setAttribute('role','alert');
				o.innerHTML='<div style="width:24px;height:24px;border:2px solid transparent;border-top-color:#000;border-radius:50%;animation:oidc-s .8s linear infinite"></div>';
				o.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:999999;display:flex;align-items:center;justify-content:center';
				var s=document.createElement('style');s.textContent='@keyframes oidc-s{to{transform:rotate(360deg)}}';
				document.head.appendChild(s);document.body.appendChild(o);
				var x=new XMLHttpRequest();
				x.open('POST','<?php echo $ajax_url; ?>',true);
				x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
				x.timeout=15000;
				function nav(){window.location.href='<?php echo $home_url; ?>';}
				x.onload=x.onerror=x.ontimeout=nav;
				x.send('action=oidc_logout&nonce=<?php echo $nonce; ?>');
			}
			document.addEventListener('click',function(e){
				var t=e.target;
				while(t&&t!==document&&t.tagName!=='A')t=t.parentElement;
				if(t&&t.href&&t.href.indexOf('action=logout')!==-1){e.preventDefault();e.stopPropagation();go();}
			},true);
		})();
		</script>
		<?php
	}


	public function cleanup_token_on_logout()
	{
		$wp_session_token = wp_get_session_token();
		if (!empty($wp_session_token)) {
			$this->token_storage->delete_token($wp_session_token);
		}
	}


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


	public function authentication_request_callback()
	{
		$client = $this->client;


		$authentication_request = $client->validate_authentication_request($_GET);

		if (is_wp_error($authentication_request)) {
			$this->error_redirect($authentication_request);
		}


		$code = $client->get_authentication_code($authentication_request);

		if (is_wp_error($code)) {
			$this->error_redirect($code);
		}


		$state = $client->get_authentication_state($authentication_request);

		if (is_wp_error($state)) {
			$this->error_redirect($state);
		}


		$token_result = $client->request_authentication_token($code);

		if (is_wp_error($token_result)) {
			$this->error_redirect($token_result);
		}


		$token_response = $client->get_token_response($token_result);

		$resolved = $this->resolve_user_from_token_response($token_response, array('source' => 'callback'));

		if (is_wp_error($resolved)) {
			$this->error_redirect($resolved);
		}

		$user             = $resolved['user'];
		$token_response   = $resolved['token_response'];
		$id_token_claim   = $resolved['id_token_claim'];
		$user_claim       = $resolved['user_claim'];
		$subject_identity = $resolved['subject_identity'];


		$start_time = microtime(true);
		$this->login_user($user, $token_response, $id_token_claim, $user_claim, $subject_identity);
		$end_time = microtime(true);

		$this->logger->log("Successful login for: {$user->user_login} ({$user->ID})", 'login-success', $end_time - $start_time);


		$start_time = microtime(true);
		do_action('openid-connect-generic-user-logged-in', $user);
		$end_time = microtime(true);
		$this->logger->log('openid-connect-generic-user-logged-in', 'do_action', $end_time - $start_time);


		$redirect_url = home_url();

		$state_object = get_transient('openid-connect-generic-state--' . $state);

		if (!empty($state_object) && !empty($state_object[$state]) && !empty($state_object[$state]['redirect_to'])) {
			$redirect_url = $state_object[$state]['redirect_to'];
		}


		if (!empty($_COOKIE[self::COOKIE_REDIRECT_KEY])) {
			$redirect_url = esc_url_raw(wp_unslash($_COOKIE[self::COOKIE_REDIRECT_KEY]));
		}


		if ($this->settings->redirect_user_back) {
			do_action('openid-connect-generic-redirect-user-back', $redirect_url, $user);
		}

		wp_redirect($redirect_url);

		exit;
	}


	public function resolve_user_from_token_response($token_response, $context = array())
	{
		$client = $this->client;


		$token_response = apply_filters('openid-connect-modify-token-response-before-validation', $token_response);

		if (is_wp_error($token_response)) {
			return $token_response;
		}


		$valid = $client->validate_token_response($token_response);

		if (is_wp_error($valid)) {
			return $valid;
		}


		$id_token_claim = $client->get_id_token_claim($token_response);


		$id_token_claim = apply_filters('openid-connect-modify-id-token-claim-before-validation', $id_token_claim);

		if (is_wp_error($id_token_claim)) {
			return $id_token_claim;
		}


		$valid = $client->validate_id_token_claim($id_token_claim);

		if (is_wp_error($valid)) {
			return $valid;
		}


		if (!empty($this->settings->endpoint_userinfo) && isset($token_response['access_token'])) {
			$user_claim = $client->get_user_claim($token_response);
		} else {
			return new WP_Error('userinfo_required', __('Userinfo endpoint and access_token are required.', 'daggerhart-openid-connect-generic'));
		}
		if (is_wp_error($user_claim)) {
			return $user_claim;
		}


		$valid = $client->validate_user_claim($user_claim, $id_token_claim);

		if (is_wp_error($valid)) {
			return $valid;
		}


		$subject_identity = $client->get_subject_identity($id_token_claim);
		$user = $this->get_user_by_identity($subject_identity);


		if (!$user) {

			if ($this->settings->link_existing_users || $this->settings->create_if_does_not_exist) {
				$user = $this->create_new_user($subject_identity, $user_claim);
				if (is_wp_error($user)) {
					return $user;
				}
			} else {
				return new WP_Error('identity-not-map-existing-user', __('User identity is not linked to an existing WordPress user.', 'daggerhart-openid-connect-generic'), $user_claim);
			}
		}


		$valid = $this->validate_user($user);

		if (is_wp_error($valid)) {
			return $valid;
		}

		return array(
			'user'             => $user,
			'token_response'   => $token_response,
			'id_token_claim'   => $id_token_claim,
			'user_claim'       => $user_claim,
			'subject_identity' => $subject_identity,
		);
	}


	public function validate_user($user)
	{

		if (!is_a($user, 'WP_User') || !$user->exists()) {
			return new WP_Error('invalid-user', __('Invalid user.', 'daggerhart-openid-connect-generic'), $user);
		}

		return true;
	}


	public function refresh_user_claim($user, $token_response)
	{
		$client = $this->client;


		$id_token_claim = $client->get_id_token_claim($token_response);


		$id_token_claim = apply_filters('openid-connect-modify-id-token-claim-before-validation', $id_token_claim);

		if (is_wp_error($id_token_claim)) {
			return $id_token_claim;
		}


		$valid = $client->validate_id_token_claim($id_token_claim);

		if (is_wp_error($valid)) {
			return $valid;
		}


		if (!empty($this->settings->endpoint_userinfo) && isset($token_response['access_token'])) {
			$user_claim = $client->get_user_claim($token_response);
		} else {
			$user_claim = $id_token_claim;
		}

		if (is_wp_error($user_claim)) {
			return $user_claim;
		}


		$valid = $client->validate_user_claim($user_claim, $id_token_claim);

		if (is_wp_error($valid)) {
			$this->error_redirect($valid);
			return $valid;
		}


		$token_response['time'] = time();


		$this->save_token_to_db(wp_get_session_token(), $user->ID, $token_response);
		update_user_meta($user->ID, 'openid-connect-generic-last-id-token-claim', $id_token_claim);
		update_user_meta($user->ID, 'openid-connect-generic-last-user-claim', $user_claim);

		return $user_claim;
	}


	public function login_user($user, $token_response, $id_token_claim, $user_claim, $subject_identity): void
	{

		$token_response['time'] = time();

		update_user_meta($user->ID, 'openid-connect-generic-last-id-token-claim', $id_token_claim);
		update_user_meta($user->ID, 'openid-connect-generic-last-user-claim', $user_claim);


		$this->assign_user_role_from_claim($user, $user_claim);


		$this->sync_user_meta_from_claims($user, $user_claim);


		do_action('openid-connect-generic-update-user-using-current-claim', $user, $user_claim);



		$remember_me = apply_filters('openid-connect-generic-remember-me', true, $user, $token_response, $id_token_claim, $user_claim, $subject_identity);


		$expiration = $this->get_wp_session_expiration_from_oidc($token_response);


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


	private function get_wp_session_expiration_from_oidc($token_response)
	{

		if (!empty($token_response['refresh_expires_in'])) {
			return time() + intval($token_response['refresh_expires_in']);
		}



		$session_lifetime = apply_filters(
			'openid-connect-generic-session-lifetime',
			7 * DAY_IN_SECONDS
		);

		return time() + $session_lifetime;
	}


	public function get_user_by_identity($subject_identity)
	{

		$user_query = new WP_User_Query(
			array(
				'meta_query' => array(
					array(
						'key' => 'openid-connect-generic-subject-identity',
						'value' => $subject_identity,
					),
				),

				'blog_id' => 0,
			)
		);


		if ($user_query->get_total() > 0) {
			$users = $user_query->get_results();
			return $users[0];
		}

		return false;
	}


	private function get_username_from_claim($user_claim)
	{


		$desired_username = '';


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

			return new WP_Error('no-username', __('No appropriate username found.', 'daggerhart-openid-connect-generic'), $user_claim);
		}


		$_desired_username = explode('@', $desired_username);
		$desired_username = $_desired_username[0];

		$sanitized_username = sanitize_user($desired_username, true);
		if (empty($sanitized_username)) {
			// translators: %1$s is the santitized version of the username from the IDP.
			return new WP_Error('username-sanitization-failed', sprintf(__('Username %1$s could not be sanitized.', 'daggerhart-openid-connect-generic'), $desired_username), $desired_username);
		}

		return $sanitized_username;
	}


	private function get_nickname_from_claim($user_claim)
	{
		$desired_nickname = null;

		if (!empty($this->settings->nickname_key) && isset($user_claim[$this->settings->nickname_key])) {
			$desired_nickname = $user_claim[$this->settings->nickname_key];
		}

		if (empty($desired_nickname)) {
			// translators: %1$s is the configured User Claim nickname key.
			return new WP_Error('no-nickname', sprintf(__('No nickname found in user claim using key: %1$s.', 'daggerhart-openid-connect-generic'), $this->settings->nickname_key), $this->settings->nickname_key);
		}

		return $desired_nickname;
	}


	private function generate_unique_nickname_suffix($base_name)
	{
		$max_attempts = 50;
		for ($i = 0; $i < $max_attempts; $i++) {
			$suffix = str_pad(wp_rand(0, 999), 3, '0', STR_PAD_LEFT);
			$candidate = $base_name . $suffix;

			$user_query = new WP_User_Query(array(
				'meta_query' => array(
					array(
						'key' => 'nickname',
						'value' => $candidate,
					),
				),
				'blog_id' => 0,
				'number' => 1,
			));
			if ($user_query->get_total() === 0) {
				return $suffix;
			}
		}

		return str_pad(wp_rand(0, 99999), 5, '0', STR_PAD_LEFT);
	}


	private function get_claim($claimname, $userinfo, &$claimvalue)
	{

		if (array_key_exists($claimname, $userinfo)) {
			$claimvalue = $userinfo[$claimname];
			return true;
		}

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

		if (!array_key_exists($claimname, $claim_src_ptr)) {
			return false;
		}
		$src_name = $claim_src_ptr[$claimname];

		if (!array_key_exists($src_name, $userinfo['_claim_sources'])) {
			return false;
		}
		$src = $userinfo['_claim_sources'][$src_name];

		if (!array_key_exists('JWT', $src)) {
			return false;
		}

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


	private function get_displayname_from_claim($user_claim, $error_on_missing_key = false)
	{
		if (!empty($this->settings->displayname_format)) {
			return $this->format_string_with_claim($this->settings->displayname_format, $user_claim, $error_on_missing_key);
		}
		return null;
	}


	private function get_email_from_claim($user_claim, $error_on_missing_key = false)
	{
		if (!empty($this->settings->email_format)) {
			return $this->format_string_with_claim($this->settings->email_format, $user_claim, $error_on_missing_key);
		}
		return null;
	}


	public function create_new_user($subject_identity, $user_claim)
	{
		$start_time = microtime(true);
		$user_claim = apply_filters('openid-connect-generic-alter-user-claim', $user_claim);


		$username = $subject_identity;
		$email = $subject_identity;
		$nickname = $subject_identity;
		$displayname = $subject_identity;
		$values_missing = false;


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


		if ($values_missing && isset($user_claim['access_token']) && !empty($this->settings->endpoint_userinfo)) {
			$user_claim_result = $this->client->request_userinfo($user_claim['access_token']);


			if (is_wp_error($user_claim_result)) {
				return new WP_Error('bad-user-claim-result', __('Bad user claim result.', 'daggerhart-openid-connect-generic'), $user_claim_result);
			}

			$user_claim = json_decode($user_claim_result['body'], true);
		}

		$_email = $this->get_email_from_claim($user_claim, true);
		if (is_wp_error($_email)) {
			return $_email;
		}

		if (!empty($_email)) {
			$email = $_email;
		}

		$_username = $this->get_username_from_claim($user_claim);
		if (is_wp_error($_username)) {
			return $_username;
		}

		if (!empty($_username)) {
			$username = $_username;
		}


		if (!empty($this->settings->enable_nickname_format) && !empty($this->settings->nickname_format)) {
			$base_name = $this->format_string_with_claim($this->settings->nickname_format, $user_claim, true);
			if (is_wp_error($base_name)) {
				return $base_name;
			}
			$nickname = $base_name . $this->generate_unique_nickname_suffix($base_name);
			$displayname = $nickname;
		} else {
			$_nickname = $this->get_nickname_from_claim($user_claim);
			if (is_wp_error($_nickname)) {
				return $_nickname;
			}

			if (empty($_nickname)) {
				$nickname = $username;
			}

			$_displayname = $this->get_displayname_from_claim($user_claim, true);
			if (is_wp_error($_displayname)) {
				return $_displayname;
			}

			if (empty($_displayname)) {
				$displayname = $nickname;
			}
		}


		if ($this->settings->link_existing_users) {
			$uid = null;
			if ($this->settings->identify_with_username) {
				$uid = username_exists($username);
			} else {
				$uid = email_exists($email);
			}
			if (!empty($uid)) {

				$existing_sub = get_user_meta($uid, 'openid-connect-generic-subject-identity', true);
				if (!empty($existing_sub) && $existing_sub !== strval($subject_identity)) {


					$orphaned_email = 'orphaned_' . $existing_sub . '_' . get_userdata($uid)->user_email;
					wp_update_user(array('ID' => $uid, 'user_email' => $orphaned_email));
					$this->logger->log(
						"Orphaned user {$uid}: sub '{$existing_sub}' no longer matches incoming sub '{$subject_identity}'. Email changed to '{$orphaned_email}'.",
						__METHOD__
					);

				} else {
					$user = $this->update_existing_user($uid, $subject_identity);
					do_action('openid-connect-generic-update-user-using-current-claim', $user, $user_claim);
					$end_time = microtime(true);
					$this->logger->log("Existing user updated: {$user->user_login} ($uid)", __METHOD__, $end_time - $start_time);
					return $user;
				}
			}
		}


		$create_user = apply_filters('openid-connect-generic-user-creation-test', $this->settings->create_if_does_not_exist, $user_claim);

		if (!$create_user) {
			return new WP_Error('cannot-authorize', __('Can not authorize.', 'daggerhart-openid-connect-generic'), $create_user);
		}


		$_username = $username;


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


		$uid = wp_insert_user($user_data);


		if (is_wp_error($uid)) {
			return new WP_Error('failed-user-creation', __('Failed user creation.', 'daggerhart-openid-connect-generic'), $uid);
		}


		$user = get_user_by('id', $uid);


		add_user_meta($user->ID, 'openid-connect-generic-subject-identity', (string) $subject_identity, true);


		$this->assign_user_role_from_claim($user, $user_claim);


		$this->sync_user_meta_from_claims($user, $user_claim);


		$end_time = microtime(true);
		$this->logger->log("New user created: {$user->user_login} ($uid)", __METHOD__, $end_time - $start_time);


		do_action('openid-connect-generic-user-create', $user, $user_claim);

		return $user;
	}


	public function update_existing_user($uid, $subject_identity)
	{

		update_user_meta($uid, 'openid-connect-generic-subject-identity', strval($subject_identity));


		do_action('openid-connect-generic-user-update', $uid);


		return get_user_by('id', $uid);
	}


	private function assign_user_role_from_claim($user, $user_claim)
	{

		if (empty($this->settings->enable_role_mapping)) {
			return;
		}

		$role_claim_key = $this->settings->role_claim_key;
		$role_mappings = $this->settings->role_mappings;
		$default_role = $this->settings->default_role;


		if (empty($default_role)) {
			$default_role = 'subscriber';
		}


		if (empty($role_claim_key) || !isset($user_claim[$role_claim_key])) {

			$user->set_role($default_role);
			return;
		}


		$claim_value = $user_claim[$role_claim_key];


		if (!is_array($claim_value)) {
			$claim_values = array($claim_value);
		} else {
			$claim_values = $claim_value;
		}


		$first_claim_value = !empty($claim_values) ? $claim_values[0] : '';


		if (empty($first_claim_value)) {
			$user->set_role($default_role);
			return;
		}


		$matched_role = null;
		if (!empty($role_mappings) && is_array($role_mappings)) {
			foreach ($role_mappings as $mapping) {
				if (isset($mapping['claim_value']) && isset($mapping['wp_role'])) {

					if ($mapping['claim_value'] === $first_claim_value) {
						$matched_role = $mapping['wp_role'];
						break;
					}
				}
			}
		}


		if ($matched_role) {
			$user->set_role($matched_role);
		} else {
			$user->set_role($default_role);
		}
	}


	private function sync_user_meta_from_claims($user, $user_claim)
	{
		if (empty($this->settings->enable_claim_meta_mapping)) {
			return;
		}

		$mappings = $this->settings->claim_meta_mappings;
		if (empty($mappings) || !is_array($mappings)) {
			return;
		}

		foreach ($mappings as $mapping) {
			if (empty($mapping['claim_key']) || empty($mapping['meta_key'])) {
				continue;
			}

			$claim_key = $mapping['claim_key'];
			$meta_key  = $mapping['meta_key'];

			if (array_key_exists($claim_key, $user_claim)) {
				$value = $user_claim[$claim_key];
				update_user_meta($user->ID, $meta_key, $value);

				$this->logger->log(
					array(
						'type'      => 'claim_meta_sync_set',
						'user_id'   => $user->ID,
						'username'  => $user->user_login,
						'claim_key' => $claim_key,
						'meta_key'  => $meta_key,
						'is_array'  => is_array($value),
						'count'     => is_array($value) ? count($value) : 1,
					),
					'claim_meta_sync_set',
					$user->ID
				);
			} else {
				delete_user_meta($user->ID, $meta_key);

				$this->logger->log(
					array(
						'type'      => 'claim_meta_sync_cleared',
						'user_id'   => $user->ID,
						'username'  => $user->user_login,
						'claim_key' => $claim_key,
						'meta_key'  => $meta_key,
						'reason'    => 'Claim absent from userinfo response',
					),
					'claim_meta_sync_cleared',
					$user->ID
				);
			}
		}
	}
}
