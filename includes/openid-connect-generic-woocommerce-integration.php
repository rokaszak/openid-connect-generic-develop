<?php
/**
 * WooCommerce integration class.
 *
 * @package   OpenID_Connect_Generic
 * @category  Integration
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_WooCommerce_Integration class.
 *
 * Handles WooCommerce-specific login integration.
 *
 * @package OpenID_Connect_Generic
 * @category  Integration
 */
class OpenID_Connect_Generic_WooCommerce_Integration {

	/**
	 * Plugin settings object.
	 *
	 * @var OpenID_Connect_Generic_Option_Settings
	 */
	private $settings;

	/**
	 * Plugin client wrapper instance.
	 *
	 * @var OpenID_Connect_Generic_Client_Wrapper
	 */
	private $client_wrapper;

	/**
	 * The class constructor.
	 *
	 * @param OpenID_Connect_Generic_Option_Settings $settings       A plugin settings object instance.
	 * @param OpenID_Connect_Generic_Client_Wrapper  $client_wrapper A plugin client wrapper object instance.
	 */
	public function __construct( $settings, $client_wrapper ) {
		$this->settings = $settings;
		$this->client_wrapper = $client_wrapper;
	}

	/**
	 * Create an instance and register hooks.
	 *
	 * @param OpenID_Connect_Generic_Option_Settings $settings       A plugin settings object instance.
	 * @param OpenID_Connect_Generic_Client_Wrapper  $client_wrapper A plugin client wrapper object instance.
	 *
	 * @return OpenID_Connect_Generic_WooCommerce_Integration|null
	 */
	public static function register( $settings, $client_wrapper ) {
		// Only register if WooCommerce is active.
		if ( ! class_exists( 'WooCommerce' ) ) {
			return null;
		}

		$integration = new self( $settings, $client_wrapper );

		// Add OIDC button if enabled.
		if ( ! empty( $settings->enable_woocommerce_oidc ) ) {
			add_action( 'woocommerce_login_form_start', array( $integration, 'add_oidc_button_to_login' ) );
			add_action( 'woocommerce_before_customer_login_form', array( $integration, 'add_oidc_button_to_account' ) );
		}

		// Block WooCommerce password authentication if enabled.
		if ( ! empty( $settings->disable_woocommerce_password_auth ) ) {
			add_action( 'woocommerce_login_form_start', array( $integration, 'hide_woocommerce_login_form_fields' ) );
			add_filter( 'woocommerce_process_login_errors', array( $integration, 'block_woocommerce_password_login' ), 10, 3 );
		}

		return $integration;
	}

	/**
	 * Add OIDC button to WooCommerce login form.
	 *
	 * @return void
	 */
	public function add_oidc_button_to_login() {
		echo wp_kses_post( $this->render_oidc_button() );
	}

	/**
	 * Add OIDC button before customer login form on My Account page.
	 *
	 * @return void
	 */
	public function add_oidc_button_to_account() {
		// Only show if not already logged in.
		if ( ! is_user_logged_in() ) {
			echo '<div style="text-align: center; margin-bottom: 2em;">';
			echo wp_kses_post( $this->render_oidc_button() );
			echo '</div>';
		}
	}

	/**
	 * Block WooCommerce password login attempts.
	 *
	 * @param WP_Error $validation_error Error object.
	 * @param string   $username         Username.
	 * @param string   $password         Password.
	 *
	 * @return WP_Error
	 */
	public function block_woocommerce_password_login( $validation_error, $username, $password ) {
		// Block all password login attempts.
		$validation_error->add(
			'oidc_only_login',
			__( '<strong>Error:</strong> Password authentication is disabled. Please use OpenID Connect to login.', 'daggerhart-openid-connect-generic' )
		);

		return $validation_error;
	}

	/**
	 * Hide WooCommerce login form fields via CSS injection.
	 * This properly hides the username/password fields without relying on output buffering.
	 *
	 * @return void
	 */
	public function hide_woocommerce_login_form_fields() {
		?>
		<style type="text/css">
			/* Hide WooCommerce login form fields */
			.woocommerce-form-login .form-row-first,
			.woocommerce-form-login .form-row-last,
			.woocommerce-form-login .woocommerce-form-row--wide,
			.woocommerce-form-login__username,
			.woocommerce-form-login__password,
			.woocommerce-form-login__rememberme,
			.woocommerce-form-login__submit,
			.woocommerce-form-login .woocommerce-form__label-for-checkbox,
			.woocommerce-form-login .woocommerce-Button,
			.woocommerce-form-login .form-row:not(.openid-connect-login-button),
			.woocommerce-LostPassword,
			.woocommerce-form-login p:not(.openid-connect-login-button) {
				display: none !important;
			}
			
			/* Proper WooCommerce button styling with logo support */
			.openid-connect-login-button {
				text-align: center;
				margin: 1em 0;
			}
			
			.openid-connect-login-button .button,
			.openid-connect-login-button .woocommerce-button {
				display: inline-flex !important;
				align-items: center;
				justify-content: center;
				flex-wrap: nowrap;
				gap: 0.5em;
			}
			
			.openid-connect-login-button__logo {
				display: inline-block;
				flex-shrink: 0;
				max-width: 2em;
				max-height: 2em;
				width: auto;
				height: auto;
			}
			
			.openid-connect-login-button__logo img,
			.openid-connect-login-button__logo svg {
				display: block;
				width: 100%;
				height: 100%;
				object-fit: contain;
			}
			
			.openid-connect-login-button__text {
				display: inline-block;
			}
		</style>
		<?php
	}

	/**
	 * Render the OIDC button for WooCommerce.
	 *
	 * @return string
	 */
	private function render_oidc_button() {
		// Use custom button text from settings if available.
		$button_text = ! empty( $this->settings->login_button_text ) 
			? $this->settings->login_button_text 
			: __( 'Login with OpenID Connect', 'daggerhart-openid-connect-generic' );

		$text = apply_filters( 'openid-connect-generic-login-button-text', $button_text );
		$text = esc_html( $text );

		$href = $this->client_wrapper->get_authentication_url();
		$href = esc_url( $href );

		// Build logo HTML if image is set.
		$logo_html = '';
		if ( ! empty( $this->settings->login_button_image_id ) ) {
			$image_id = intval( $this->settings->login_button_image_id );
			
			// Get full size to support SVGs and proper sizing via CSS.
			$image = wp_get_attachment_image( $image_id, 'full', false, array(
				'class' => 'openid-connect-login-button__logo-img',
				'alt'   => '',
			) );
			
			if ( $image ) {
				$logo_html = '<span class="openid-connect-login-button__logo">' . $image . '</span>';
			}
		}

		$text_html = '<span class="openid-connect-login-button__text">' . $text . '</span>';
		$button_inner = $logo_html ? $logo_html . $text_html : $text_html;

		$button_html = sprintf(
			'<div class="woocommerce-form-row form-row openid-connect-login-button"><a href="%s" class="button woocommerce-button button-primary">%s</a></div>',
			$href,
			$button_inner
		);

		return $button_html;
	}
}

