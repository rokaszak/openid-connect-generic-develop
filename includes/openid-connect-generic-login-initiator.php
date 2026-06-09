<?php

class OpenID_Connect_Generic_Login_Initiator {


	const ACTION = 'oidc_start_login';


	private $client_wrapper;


	private $logger;


	public function __construct( $client_wrapper, $logger ) {
		$this->client_wrapper = $client_wrapper;
		$this->logger         = $logger;
	}


	public static function register( $client_wrapper, $logger ) {
		$self = new self( $client_wrapper, $logger );

		add_action( 'wp_ajax_nopriv_' . self::ACTION, array( $self, 'start_login' ) );
		add_action( 'wp_ajax_' . self::ACTION, array( $self, 'start_login' ) );

		return $self;
	}



	public static function get_url() {
		return admin_url( 'admin-ajax.php?action=' . self::ACTION );
	}


	public function start_login() {

		$redirect_to = $this->resolve_origin();

		$atts = array();
		if ( ! empty( $redirect_to ) ) {
			$atts['redirect_to'] = $redirect_to;
		}

		$auth_url = $this->client_wrapper->get_authentication_url( $atts );

		$this->logger->log(
			array(
				'type'        => 'login_initiated_on_demand',
				'redirect_to' => $redirect_to,
			),
			'login_initiator',
			null
		);

		wp_redirect( $auth_url );
		exit;
	}


	private function resolve_origin() {

		$candidate = '';

		if ( isset( $_REQUEST['redirect_to'] ) ) {
			$candidate = esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) );
		} elseif ( ! empty( $_SERVER['HTTP_REFERER'] ) ) {
			$candidate = esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) );
		}

		if ( empty( $candidate ) ) {
			return '';
		}

		return wp_validate_redirect( $candidate, '' );
	}
}
