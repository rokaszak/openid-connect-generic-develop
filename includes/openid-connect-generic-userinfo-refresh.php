<?php

class OpenID_Connect_Generic_Userinfo_Refresh {


	const ACTION = 'oidc_refresh_userinfo';


	private $client_wrapper;


	private $logger;


	public function __construct( $client_wrapper, $logger ) {
		$this->client_wrapper = $client_wrapper;
		$this->logger         = $logger;
	}


	public static function register( $client_wrapper, $logger ) {
		$self = new self( $client_wrapper, $logger );

		add_action( 'wp_ajax_' . self::ACTION, array( $self, 'refresh' ) );
		add_action( 'wp_ajax_nopriv_' . self::ACTION, array( $self, 'refresh' ) );

		return $self;
	}


	public static function get_url() {
		return admin_url( 'admin-ajax.php?action=' . self::ACTION );
	}


	public function refresh() {

		$origin = $this->resolve_origin();

		if ( is_user_logged_in() ) {
			$result = $this->client_wrapper->refresh_userinfo_for_current_user();

			$this->logger->log(
				array(
					'type'    => 'userinfo_refresh_requested',
					'success' => ! is_wp_error( $result ),
				),
				'userinfo_refresh',
				null
			);
		}

		wp_safe_redirect( ! empty( $origin ) ? $origin : home_url() );
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
