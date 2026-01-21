<?php
/**
 * Login form and login button handling class.
 *
 * @package   OpenID_Connect_Generic
 * @category  Login
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_Login_Form class.
 *
 * Login form and login button handling.
 *
 * @package OpenID_Connect_Generic
 * @category  Login
 */
class OpenID_Connect_Generic_Login_Form {

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
	 * Create an instance of the OpenID_Connect_Generic_Login_Form class.
	 *
	 * @param OpenID_Connect_Generic_Option_Settings $settings       A plugin settings object instance.
	 * @param OpenID_Connect_Generic_Client_Wrapper  $client_wrapper A plugin client wrapper object instance.
	 *
	 * @return void
	 */
	public static function register( $settings, $client_wrapper ) {
		$login_form = new self( $settings, $client_wrapper );

		// Enqueue login button styles.
		add_action( 'login_enqueue_scripts', array( $login_form, 'enqueue_login_styles' ) );
		add_action( 'wp_enqueue_scripts', array( $login_form, 'enqueue_login_styles' ) );

		// Alter the login form as dictated by settings.
		add_filter( 'login_message', array( $login_form, 'handle_login_page' ), 99 );

		// Add a shortcode for the login button.
		add_shortcode( 'openid_connect_generic_login_button', array( $login_form, 'make_login_button' ) );

		$login_form->handle_redirect_login_type_auto();

		// Block password authentication if enabled.
		if ( ! empty( $settings->disable_password_auth ) ) {
			add_action( 'login_head', array( $login_form, 'hide_wordpress_login_form_fields' ) );
			add_filter( 'authenticate', array( $login_form, 'block_password_authentication' ), 100, 3 );
		}

		// Block password reset if enabled.
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

	/**
	 * Enqueue login button styles.
	 *
	 * @return void
	 */
	public function enqueue_login_styles() {
		wp_enqueue_style( 
			'openid-connect-generic-login-button', 
			plugin_dir_url( __DIR__ ) . 'css/login-button.css', 
			array(), 
			OpenID_Connect_Generic::VERSION, 
			'all' 
		);
	}

	/**
	 * Auto Login redirect.
	 *
	 * @return void
	 */
	public function handle_redirect_login_type_auto() {

		if ( 'wp-login.php' == $GLOBALS['pagenow']
			&& ( 'auto' == $this->settings->login_type || ! empty( $_GET['force_redirect'] ) )
			// Don't send users to the IDP on logout or post password protected authentication.
			&& ( ! isset( $_GET['action'] ) || ! in_array( $_GET['action'], array( 'logout', 'postpass' ) ) )
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WP Login Form doesn't have a nonce.
			&& ! isset( $_POST['wp-submit'] ) ) {
			if ( ! isset( $_GET['login-error'] ) ) {
				wp_redirect( $this->client_wrapper->get_authentication_url() );
				exit;
			}
		}
	}

	/**
	 * Implements filter login_message.
	 *
	 * @param string $message The text message to display on the login page.
	 *
	 * @return string
	 */
	public function handle_login_page( $message ) {

		if ( isset( $_GET['login-error'] ) ) {
			$error_message = ! empty( $_GET['message'] ) ? sanitize_text_field( wp_unslash( $_GET['message'] ) ) : 'Unknown error.';
			$message .= $this->make_error_output( sanitize_text_field( wp_unslash( $_GET['login-error'] ) ), $error_message );
		}

		// Login button is appended to existing messages in case of error.
		$message .= $this->make_login_button();

		return $message;
	}

	/**
	 * Display an error message to the user.
	 *
	 * @param string $error_code    The error code.
	 * @param string $error_message The error message test.
	 *
	 * @return string
	 */
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

	/**
	 * Create a login button (link).
	 *
	 * @param array $atts Array of optional attributes to override login buton
	 * functionality when used by shortcode.
	 *
	 * @return string
	 */
	public function make_login_button( $atts = array() ) {

		$atts = shortcode_atts(
			array(
				'button_text' => __( 'Login with Airomi Connect', 'daggerhart-openid-connect-generic' ),
			),
			$atts,
			'openid_connect_generic_login_button'
		);

		// Use custom button text from settings if available.
		$button_text = ! empty( $this->settings->login_button_text ) ? $this->settings->login_button_text : $atts['button_text'];
		$text = apply_filters( 'openid-connect-generic-login-button-text', $button_text );
		$text = esc_html( $text );

		$href = $this->client_wrapper->get_authentication_url( $atts );
		$href = esc_url_raw( $href );

		// Build logo HTML if image is set.
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

		// Text comes first, then logo (can be reversed with CSS flex-direction).
		$text_html = '<span class="openid-connect-login-button__text">' . $text . '</span>';
		$button_inner = $text_html . ( $logo_html ? $logo_html : '' );

		$login_button = sprintf(
			'<div class="openid-connect-login-button"><a class="button button-large" href="%s">%s</a></div>',
			$href,
			$button_inner
		);

		return $login_button;
	}

	/**
	 * Hide WordPress login form via CSS injection.
	 * Since password auth is disabled, just hide the entire form.
	 *
	 * @return void
	 */
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

	/**
	 * Hide WordPress password reset links via CSS injection.
	 *
	 * @return void
	 */
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

	/**
	 * Block password authentication while allowing Application Passwords for REST API/XML-RPC.
	 *
	 * @param WP_User|WP_Error|null $user     The user being authenticated.
	 * @param string                $username The username.
	 * @param string                $password The password.
	 *
	 * @return WP_User|WP_Error
	 */
	public function block_password_authentication( $user, $username, $password ) {
		// Allow if this is a REST API or XML-RPC request (Application Passwords).
		if ( defined( 'REST_REQUEST' ) || defined( 'XMLRPC_REQUEST' ) ) {
			return $user;
		}

		// If user is already authenticated (e.g., by Application Passwords), allow it.
		if ( is_a( $user, 'WP_User' ) ) {
			return $user;
		}

		// If this is a password authentication attempt, block it.
		if ( ! empty( $username ) && ! empty( $password ) ) {
			// Remove the default WordPress password authentication filters.
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

	/**
	 * Block password reset functionality.
	 *
	 * @param bool $allow   Whether to allow password reset.
	 * @param int  $user_id The user ID.
	 *
	 * @return bool
	 */
	public function block_password_reset( $allow, $user_id ) {
		return false;
	}

	/**
	 * Redirect from password reset pages to login page.
	 *
	 * @return void
	 */
	public function redirect_from_password_reset() {
		wp_safe_redirect( wp_login_url() );
		exit;
	}

	/**
	 * Hide password fields for users in profile.
	 *
	 * @param bool $show Whether to show password fields.
	 *
	 * @return bool
	 */
	public function hide_password_fields_for_users( $show ) {
		return false;
	}
}
