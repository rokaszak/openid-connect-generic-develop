<?php

class OpenID_Connect_Generic_Login_Form {


	private $settings;


	private $client_wrapper;


	public function __construct( $settings, $client_wrapper ) {
		$this->settings = $settings;
		$this->client_wrapper = $client_wrapper;
	}


	public static function register( $settings, $client_wrapper ) {
		$login_form = new self( $settings, $client_wrapper );


		add_action( 'login_enqueue_scripts', array( $login_form, 'enqueue_login_styles' ) );
		add_action( 'wp_enqueue_scripts', array( $login_form, 'enqueue_login_styles' ) );


		add_filter( 'login_message', array( $login_form, 'handle_login_page' ), 99 );


		add_shortcode( 'openid_connect_generic_login_button', array( $login_form, 'make_login_button' ) );

		$login_form->handle_redirect_login_type_auto();


		if ( ! empty( $settings->disable_password_auth ) ) {
			add_action( 'login_head', array( $login_form, 'hide_wordpress_login_form_fields' ) );
			add_filter( 'authenticate', array( $login_form, 'block_password_authentication' ), 100, 3 );
		}


		if ( ! empty( $settings->disable_password_reset ) ) {
			add_action( 'login_head', array( $login_form, 'hide_wordpress_password_reset_links' ) );
			add_filter( 'allow_password_reset', array( $login_form, 'block_password_reset' ), 10, 2 );
			add_action( 'login_form_lostpassword', array( $login_form, 'redirect_from_password_reset' ) );
			add_action( 'login_form_retrievepassword', array( $login_form, 'redirect_from_password_reset' ) );
			add_action( 'login_form_resetpass', array( $login_form, 'redirect_from_password_reset' ) );
			add_action( 'login_form_rp', array( $login_form, 'redirect_from_password_reset' ) );
			add_filter( 'show_password_fields', array( $login_form, 'hide_password_fields_for_users' ) );
		}
	}


	public function enqueue_login_styles() {
		wp_enqueue_style(
			'openid-connect-generic-login-button',
			plugin_dir_url( __DIR__ ) . 'css/login-button.css',
			array(),
			OpenID_Connect_Generic::VERSION,
			'all'
		);
	}


	public function handle_redirect_login_type_auto() {

		if ( 'wp-login.php' == $GLOBALS['pagenow']
			&& ( 'auto' == $this->settings->login_type || ! empty( $_GET['force_redirect'] ) )

			&& ( ! isset( $_GET['action'] ) || ! in_array( $_GET['action'], array( 'logout', 'postpass' ) ) )

			&& ! isset( $_POST['wp-submit'] ) ) {
			if ( ! isset( $_GET['login-error'] ) ) {
				wp_redirect( $this->client_wrapper->get_authentication_url() );
				exit;
			}
		}
	}


	public function handle_login_page( $message ) {

		if ( isset( $_GET['login-error'] ) ) {
			$error_message = ! empty( $_GET['message'] ) ? sanitize_text_field( wp_unslash( $_GET['message'] ) ) : 'Unknown error.';
			$message .= $this->make_error_output( sanitize_text_field( wp_unslash( $_GET['login-error'] ) ), $error_message );
		}


		$message .= $this->make_login_button();

		return $message;
	}


	public function make_error_output( $error_code, $error_message ) {

		ob_start();
		?>
		<div id="login_error"><?php // translators: %1$s is the error code from the IDP. ?>
			<strong><?php printf( esc_html__( 'ERROR (%1$s)', 'daggerhart-openid-connect-generic' ), esc_html( $error_code ) ); ?>: </strong>
			<?php print esc_html( $error_message ); ?>
		</div>
		<?php
		return wp_kses_post( ob_get_clean() );
	}


	public function make_login_button( $atts = array() ) {

		$atts = shortcode_atts(
			array(
				'button_text' => __( 'Login with Airomi Connect', 'daggerhart-openid-connect-generic' ),
			),
			$atts,
			'openid_connect_generic_login_button'
		);


		$button_text = ! empty( $this->settings->login_button_text ) ? $this->settings->login_button_text : $atts['button_text'];
		$text = apply_filters( 'openid-connect-generic-login-button-text', $button_text );
		$text = esc_html( $text );

		if ( 'wp-login.php' !== $GLOBALS['pagenow'] && class_exists( 'OpenID_Connect_Generic_Login_Initiator' ) ) {
			$href = OpenID_Connect_Generic_Login_Initiator::get_url();
		} else {
			$href = $this->client_wrapper->get_authentication_url( $atts );
		}
		$href = esc_url_raw( $href );


		$logo_html = '';
		if ( ! empty( $this->settings->login_button_image_id ) ) {
			$image_id = intval( $this->settings->login_button_image_id );

			$image_src = wp_get_attachment_image_src( $image_id, 'full' );

			if ( $image_src ) {
				$image_url = esc_url( $image_src[0] );
				$image_alt = get_post_meta( $image_id, '_wp_attachment_image_alt', true );
				$image_alt = $image_alt ? esc_attr( $image_alt ) : '';

				$logo_html = sprintf(
					'<span class="openid-connect-login-button__logo"><img src="%s" alt="%s" class="openid-connect-login-button__logo-img"></span>',
					$image_url,
					$image_alt
				);
			}
		}


		$text_html = '<span class="openid-connect-login-button__text">' . $text . '</span>';
		$button_inner = $text_html . ( $logo_html ? $logo_html : '' );

		$login_button = sprintf(
			'<div class="openid-connect-login-button"><a class="button button-large" href="%s">%s</a></div>',
			$href,
			$button_inner
		);

		return $login_button;
	}


	public function hide_wordpress_login_form_fields() {
		?>
		<style type="text/css">
			/* Hide WordPress logo */
			#login h1,
			#login h1 a {
				display: none !important;
			}

			/* Hide entire login form - no ugly empty square */
			#loginform {
				display: none !important;
			}
		</style>
		<?php
	}


	public function hide_wordpress_password_reset_links() {
		?>
		<style type="text/css">
			/* Hide lost password link */
			#login #nav,
			#login #nav a,
			.login #nav,
			.login #backtoblog {
				display: none !important;
			}
		</style>
		<?php
	}


	public function block_password_authentication( $user, $username, $password ) {

		if ( defined( 'REST_REQUEST' ) || defined( 'XMLRPC_REQUEST' ) ) {
			return $user;
		}


		if ( is_a( $user, 'WP_User' ) ) {
			return $user;
		}


		if ( ! empty( $username ) && ! empty( $password ) ) {

			remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
			remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );

			return new WP_Error(
				'oidc_only_login',
				__( '<strong>Error:</strong> Password authentication is disabled. Please use Airomi Connect to login.', 'daggerhart-openid-connect-generic' ),
				array( 'oidc_only' => true )
			);
		}

		return $user;
	}


	public function block_password_reset( $allow, $user_id ) {
		return false;
	}


	public function redirect_from_password_reset() {
		wp_safe_redirect( wp_login_url() );
		exit;
	}


	public function hide_password_fields_for_users( $show ) {
		return false;
	}
}
