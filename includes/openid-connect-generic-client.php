<?php

class OpenID_Connect_Generic_Client {

	const CONNECT_TIMEOUT = 5.0;


	const DEFAULT_RESPONSE_TIMEOUT = 10.0;


	private $client_id;


	private $client_secret;


	private $scope;


	private $endpoint_login;


	private $endpoint_userinfo;


	private $endpoint_token;


	private $redirect_uri;


	private $acr_values;


	private $state_time_limit = 180;


	private $logger;


	public function __construct( $client_id, $client_secret, $scope, $endpoint_login, $endpoint_userinfo, $endpoint_token, $redirect_uri, $acr_values, $state_time_limit, $logger ) {
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->scope = $scope;
		$this->endpoint_login = $endpoint_login;
		$this->endpoint_userinfo = $endpoint_userinfo;
		$this->endpoint_token = $endpoint_token;
		$this->redirect_uri = $redirect_uri;
		$this->acr_values = $acr_values;
		$this->state_time_limit = $state_time_limit;
		$this->logger = $logger;
	}


	public function get_redirect_uri() {
		return $this->redirect_uri;
	}


	public function get_endpoint_login_url() {
		return $this->endpoint_login;
	}


	public function validate_authentication_request( $request ) {

		if ( isset( $request['error'] ) ) {
			return new WP_Error( 'unknown-error', 'An unknown error occurred.', $request );
		}


		if ( ! isset( $request['code'] ) ) {
			return new WP_Error( 'no-code', 'No authentication code present in the request.', $request );
		}


		if ( ! isset( $request['state'] ) ) {
			do_action( 'openid-connect-generic-no-state-provided' );
			return new WP_Error( 'missing-state', __( 'Missing state.', 'daggerhart-openid-connect-generic' ), $request );
		}

		if ( ! $this->check_state( $request['state'] ) ) {
			return new WP_Error( 'invalid-state', __( 'Invalid state.', 'daggerhart-openid-connect-generic' ), $request );
		}

		return $request;
	}


	public function get_authentication_code( $request ) {
		if ( ! isset( $request['code'] ) ) {
			return new WP_Error( 'missing-authentication-code', __( 'Missing authentication code.', 'daggerhart-openid-connect-generic' ), $request );
		}

		return $request['code'];
	}


	public function request_authentication_token( $code ) {


		$parsed_url = parse_url( $this->endpoint_token );
		$host = $parsed_url['host'];

		$request = array(
			'body' => array(
				'code'          => $code,
				'client_id'     => $this->client_id,
				'client_secret' => $this->client_secret,
				'redirect_uri'  => $this->redirect_uri,
				'grant_type'    => 'authorization_code',
				'scope'         => $this->scope,
			),
			'headers' => array( 'Host' => $host ),
		);

		if ( ! empty( $this->acr_values ) ) {
			$request['body'] += array( 'acr_values' => $this->acr_values );
		}


		$request = apply_filters( 'openid-connect-generic-alter-request', $request, 'get-authentication-token' );

		$start_time = microtime( true );
		$response   = $this->http_request( 'POST', $this->endpoint_token, $request );
		$processing_time = microtime( true ) - $start_time;

		$this->logger->log(
			array(
				'type'         => 'authentication_request',
				'endpoint'     => $this->endpoint_token,
				'request_body' => $this->sanitize_request_body_for_logging( $request['body'] ?? array() ),
			),
			'request_authentication_token_debug',
			$processing_time
		);

		if ( is_wp_error( $response ) ) {
			$response->add( 'request_authentication_token', __( 'Request for authentication token failed.', 'daggerhart-openid-connect-generic' ) );
		}

		return $response;
	}


	public function request_new_tokens( $refresh_token ) {
		$request = array(
			'body' => array(
				'refresh_token' => $refresh_token,
				'client_id'     => $this->client_id,
				'client_secret' => $this->client_secret,
				'grant_type'    => 'refresh_token',
			),
		);


		$request = apply_filters( 'openid-connect-generic-alter-request', $request, 'refresh-token' );

		$start_time = microtime( true );
		$response   = $this->http_request( 'POST', $this->endpoint_token, $request );
		$processing_time = microtime( true ) - $start_time;

		$this->logger->log(
			array(
				'type'         => 'request_new_tokens_details',
				'endpoint'     => $this->endpoint_token,
				'request_body' => $this->sanitize_request_body_for_logging( $request['body'] ?? array() ),
			),
			'request_new_tokens_debug',
			$processing_time
		);

		if ( is_wp_error( $response ) ) {
			$response->add( 'refresh_token', __( 'Refresh token failed.', 'daggerhart-openid-connect-generic' ) );
		}

		return $response;
	}


	private function sanitize_request_body_for_logging( $request_body ) {
		if ( isset( $request_body['client_secret'] ) ) {
			$request_body['client_secret'] = '[REDACTED]';
		}

		return $request_body;
	}

public function get_token_response( $token_result ) {
	if ( ! isset( $token_result['body'] ) ) {
		return new WP_Error( 'missing-token-body', __( 'Missing token body.', 'daggerhart-openid-connect-generic' ), $token_result );
	}


	$response_code = wp_remote_retrieve_response_code( $token_result );
	if ( $response_code !== 200 ) {
		$error_message = sprintf(
			__( 'Token request failed with HTTP %d: %s', 'daggerhart-openid-connect-generic' ),
			$response_code,
			wp_remote_retrieve_response_message( $token_result )
		);


		$this->logger->log(
			array(
				'type'              => 'token_response_error',
				'http_code'         => $response_code,
				'http_message'      => wp_remote_retrieve_response_message( $token_result ),
				'response_body'     => $token_result['body'],
				'response_headers'  => wp_remote_retrieve_headers( $token_result ),
			),
			'get_token_response_error',
			null
		);

		return new WP_Error( 'http-error-' . $response_code, $error_message, $token_result );
	}


	$token_response = json_decode( $token_result['body'], true );


	if ( is_null( $token_response ) ) {
		return new WP_Error( 'invalid-token', __( 'Invalid token.', 'daggerhart-openid-connect-generic' ), $token_result );
	}


	if ( isset( $token_response['error'] ) ) {
		$error = $token_response['error'];
		$error_description = $error;
		if ( isset( $token_response['error_description'] ) ) {
			$error_description = $token_response['error_description'];
		}


		$this->logger->log(
			array(
				'type'        => 'oauth_error_response',
				'error'       => $token_response['error'] ?? '',
				'description' => $token_response['error_description'] ?? '',
				'full_response' => $token_response,
			),
			'get_token_response_oauth_error',
			null
		);

		return new WP_Error( $error, $error_description, $token_result );
	}


	if ( isset( $token_response['detail'] ) && ! isset( $token_response['access_token'] ) ) {

		$this->logger->log(
			array(
				'type'              => 'idp_error_response',
				'error_detail'      => $token_response['detail'] ?? '',
				'full_response'     => $token_response,
			),
			'get_token_response_idp_error',
			null
		);

		return new WP_Error( 'token-error', $token_response['detail'], $token_result );
	}


	$this->logger->log(
		array(
			'type'                => 'token_response_success',
			'http_code'           => $response_code,
			'full_response'       => $token_response,
		),
		'get_token_response_success',
		null
	);

	return $token_response;
}


	private function http_request( $method, $url, $request ) {
		$headers = $request['headers'] ?? array();
		$body    = $request['body'] ?? null;


		if ( is_array( $body ) ) {
			$body = http_build_query( $body, '', '&' );
			if ( ! isset( $headers['Content-Type'] ) ) {
				$headers['Content-Type'] = 'application/x-www-form-urlencoded';
			}
		}

		$response_timeout = isset( $request['timeout'] ) ? floatval( $request['timeout'] ) : self::DEFAULT_RESPONSE_TIMEOUT;
		$connect_timeout  = self::CONNECT_TIMEOUT;

		$options = array(
			'timeout'         => $response_timeout,
			'connect_timeout' => $connect_timeout,
			'useragent'       => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ),
		);

		if ( isset( $request['sslverify'] ) ) {
			$options['verify'] = $request['sslverify'];
		}

		try {
			$raw = \WpOrg\Requests\Requests::request( $url, $headers, $body, strtoupper( $method ), $options );
		} catch ( \WpOrg\Requests\Exception $e ) {
			return new WP_Error( 'http_request_failed', $e->getMessage() );
		}


		return array(
			'headers'  => $raw->headers,
			'body'     => $raw->body,
			'response' => array(
				'code'    => $raw->status_code,
				'message' => get_status_header_desc( $raw->status_code ),
			),
			'cookies'  => array(),
		);
	}


	public function request_userinfo( $access_token ) {

		$request = apply_filters( 'openid-connect-generic-alter-request', array(), 'get-userinfo' );


		if ( ! array_key_exists( 'headers', $request ) || ! is_array( $request['headers'] ) ) {
			$request['headers'] = array();
		}

		$request['headers']['Authorization'] = 'Bearer ' . $access_token;


		$parsed_url = parse_url( $this->endpoint_userinfo );
		$host = $parsed_url['host'];

		if ( ! empty( $parsed_url['port'] ) ) {
			$host .= ":{$parsed_url['port']}";
		}

		$request['headers']['Host'] = $host;

		$start_time = microtime( true );
		$response   = $this->http_request( 'GET', $this->endpoint_userinfo, $request );
		$processing_time = microtime( true ) - $start_time;


		$this->logger->log(
			array(
				'type'         => 'userinfo_request',
				'endpoint'     => $this->endpoint_userinfo,
				'access_token' => $access_token,
				'headers'      => $request['headers'],
			),
			'request_userinfo_debug',
			$processing_time
		);

		if ( is_wp_error( $response ) ) {
			$response->add( 'request_userinfo', __( 'Request for userinfo failed.', 'daggerhart-openid-connect-generic' ) );
			return $response;
		}


		$response_code = wp_remote_retrieve_response_code( $response );
		if ( $response_code !== 200 ) {
			$error_message = sprintf(
				__( 'Userinfo request failed with HTTP %d: %s', 'daggerhart-openid-connect-generic' ),
				$response_code,
				wp_remote_retrieve_response_message( $response )
			);


			$this->logger->log(
				array(
					'type'              => 'userinfo_error',
					'http_code'         => $response_code,
					'http_message'      => wp_remote_retrieve_response_message( $response ),
					'response_body'     => $response['body'] ?? '',
					'response_headers'  => wp_remote_retrieve_headers( $response ),
				),
				'request_userinfo_error',
				null
			);

			return new WP_Error( 'userinfo-http-error-' . $response_code, $error_message, $response );
		}


		$userinfo_data = json_decode( $response['body'], true );
		$this->logger->log(
			array(
				'type'           => 'userinfo_response_success',
				'http_code'      => $response_code,
				'full_response'  => $userinfo_data,
				'response_body'  => $response['body'],
				'response_headers' => wp_remote_retrieve_headers( $response ),
			),
			'request_userinfo_success',
			null
		);

		return $response;
	}


	public function new_state( $redirect_to ) {

		$state = md5( mt_rand() . microtime( true ) );
		$state_value = array(
			$state => array(
				'redirect_to' => $redirect_to,
			),
		);
		set_transient( 'openid-connect-generic-state--' . $state, $state_value, $this->state_time_limit );

		return $state;
	}


	public function check_state( $state ) {

		$state_found = true;

		if ( ! get_option( '_transient_openid-connect-generic-state--' . $state ) ) {
			do_action( 'openid-connect-generic-state-not-found', $state );
			$state_found = false;
		}

		$valid = get_transient( 'openid-connect-generic-state--' . $state );

		if ( ! $valid && $state_found ) {
			do_action( 'openid-connect-generic-state-expired', $state );
		}

		return boolval( $valid );
	}


	public function get_authentication_state( $request ) {
		if ( ! isset( $request['state'] ) ) {
			return new WP_Error( 'missing-authentication-state', __( 'Missing authentication state.', 'daggerhart-openid-connect-generic' ), $request );
		}

		return $request['state'];
	}


	public function validate_token_response( $token_response ) {

		if ( ! isset( $token_response['id_token'] ) ||
			 ! isset( $token_response['token_type'] ) || strcasecmp( $token_response['token_type'], 'Bearer' )
		) {
			return new WP_Error( 'invalid-token-response', 'Invalid token response', $token_response );
		}

		return true;
	}


	public function get_id_token_claim( $token_response ) {

		if ( ! isset( $token_response['id_token'] ) ) {
			return new WP_Error( 'no-identity-token', __( 'No identity token.', 'daggerhart-openid-connect-generic' ), $token_response );
		}


		$tmp = explode( '.', $token_response['id_token'] );

		if ( ! isset( $tmp[1] ) ) {
			return new WP_Error( 'missing-identity-token', __( 'Missing identity token.', 'daggerhart-openid-connect-generic' ), $token_response );
		}


		$id_token_claim = json_decode(
			base64_decode(
				str_replace(
					array( '-', '_' ),
					array( '+', '/' ),
					$tmp[1]
				)
			),
			true
		);

		return $id_token_claim;
	}


	public function validate_id_token_claim( $id_token_claim ) {
		if ( ! is_array( $id_token_claim ) ) {
			return new WP_Error( 'bad-id-token-claim', __( 'Bad ID token claim.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}


		if ( ! isset( $id_token_claim['sub'] ) || empty( $id_token_claim['sub'] ) ) {
			return new WP_Error( 'no-subject-identity', __( 'No subject identity.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}


		if ( ! empty( $this->acr_values ) && isset( $id_token_claim['acr'] ) ) {
			if ( $this->acr_values != $id_token_claim['acr'] ) {
				return new WP_Error( 'no-match-acr', __( 'No matching acr values.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
			}
		}

		return true;
	}


	public function get_user_claim( $token_response ) {

		$user_claim_result = $this->request_userinfo( $token_response['access_token'] );


		if ( is_wp_error( $user_claim_result ) || ! isset( $user_claim_result['body'] ) ) {
			return new WP_Error( 'bad-claim', __( 'Bad user claim.', 'daggerhart-openid-connect-generic' ), $user_claim_result );
		}

		$user_claim = json_decode( $user_claim_result['body'], true );

		return $user_claim;
	}


	public function validate_user_claim( $user_claim, $id_token_claim ) {

		if ( ! is_array( $user_claim ) ) {
			return new WP_Error( 'invalid-user-claim', __( 'Invalid user claim.', 'daggerhart-openid-connect-generic' ), $user_claim );
		}


		if ( isset( $user_claim['error'] ) ) {
			$message = __( 'Error from the IDP.', 'daggerhart-openid-connect-generic' );
			if ( ! empty( $user_claim['error_description'] ) ) {
				$message = $user_claim['error_description'];
			}
			return new WP_Error( 'invalid-user-claim-' . $user_claim['error'], $message, $user_claim );
		}


		if ( $id_token_claim['sub'] !== $user_claim['sub'] ) {
			return new WP_Error( 'incorrect-user-claim', __( 'Incorrect user claim.', 'daggerhart-openid-connect-generic' ), func_get_args() );
		}


		$login_user = apply_filters( 'openid-connect-generic-user-login-test', true, $user_claim );

		if ( ! $login_user ) {
			return new WP_Error( 'unauthorized', __( 'Unauthorized access.', 'daggerhart-openid-connect-generic' ), $login_user );
		}

		return true;
	}


	public function get_subject_identity( $id_token_claim ) {
		return $id_token_claim['sub'];
	}
}
