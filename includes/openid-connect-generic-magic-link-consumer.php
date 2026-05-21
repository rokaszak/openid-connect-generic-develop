<?php

class OpenID_Connect_Generic_Magic_Link_Consumer {


	private $settings;


	private $logger;


	private $client_wrapper;

	public function __construct( $settings, $logger, $client_wrapper ) {
		$this->settings       = $settings;
		$this->logger         = $logger;
		$this->client_wrapper = $client_wrapper;
	}


	public static function register( $settings, $logger, $client_wrapper ) {
		if ( empty( $settings->enable_magic_link ) ) {
			return null;
		}

		$instance = new self( $settings, $logger, $client_wrapper );



		add_action( 'parse_request', array( $instance, 'maybe_consume' ) );

		return $instance;
	}

	public function maybe_consume() {
		if ( empty( $_GET[ OpenID_Connect_Generic_Magic_Link_Rest::QUERY_PARAM ] ) ) {
			return;
		}

		$raw_nonce = sanitize_text_field( wp_unslash( $_GET[ OpenID_Connect_Generic_Magic_Link_Rest::QUERY_PARAM ] ) );


		if ( ! preg_match( '/^[A-Za-z0-9]{' . intval( OpenID_Connect_Generic_Magic_Link_Rest::NONCE_LENGTH ) . '}$/', $raw_nonce ) ) {
			$this->fail( 'wrong_format', null );
			return;
		}

		$transient_key = OpenID_Connect_Generic_Magic_Link_Rest::TRANSIENT_PREFIX . $raw_nonce;
		$payload       = get_transient( $transient_key );


		delete_transient( $transient_key );

		if ( empty( $payload ) || ! is_array( $payload ) || empty( $payload['user_id'] ) ) {
			$this->fail( 'not_found_or_expired', null );
			return;
		}

		$user = get_user_by( 'id', intval( $payload['user_id'] ) );
		if ( ! $user ) {
			$this->fail( 'user_missing', $payload['user_id'] );
			return;
		}

		$age_ms = (int) round( ( microtime( true ) - intval( $payload['issued_at'] ) ) * 1000 );




		$this->client_wrapper->login_user(
			$user,
			$payload['token_response'],
			$payload['id_token_claim'],
			$payload['user_claim'],
			$payload['subject_identity']
		);

		do_action( 'openid-connect-generic-user-logged-in', $user );

		$this->logger->log(
			sprintf( 'magic_link_consumed: user_id=%d age_ms=%d', $user->ID, $age_ms ),
			'magic_link'
		);

		$redirect_to = home_url( '/' );
		if ( ! empty( $_GET['airomi-app'] ) ) {
			$redirect_to = add_query_arg( 'airomi-app', sanitize_text_field( wp_unslash( $_GET['airomi-app'] ) ), $redirect_to );
		}

		wp_safe_redirect( $redirect_to );
		exit;
	}

	private function fail( $reason, $context_user_id ) {
		$this->logger->log(
			sprintf(
				'magic_link_invalid: reason=%s%s',
				$reason,
				$context_user_id ? ' user_id=' . intval( $context_user_id ) : ''
			),
			'magic_link'
		);



		status_header( 410 );
		nocache_headers();
		wp_die(
			esc_html__( 'This login link is invalid or has expired.', 'daggerhart-openid-connect-generic' ),
			esc_html__( 'Login link expired', 'daggerhart-openid-connect-generic' ),
			array( 'response' => 410 )
		);
	}
}
