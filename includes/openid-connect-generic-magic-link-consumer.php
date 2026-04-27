<?php
/**
 * Magic Link consumer.
 *
 * @package   OpenID_Connect_Generic
 * @category  Magic Link
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_Magic_Link_Consumer class.
 *
 * Listens for ?magic-link=NONCE on the front-end. When a valid, unexpired,
 * unused nonce is presented, this class consumes it (single-use), logs the
 * resolved user in via the standard wrapper login_user() path so the OIDC
 * tokens are bound to the new WP session, and redirects the browser to
 * the originally requested target.
 *
 * @package OpenID_Connect_Generic
 * @category  Magic Link
 */
class OpenID_Connect_Generic_Magic_Link_Consumer {

	/**
	 * @var OpenID_Connect_Generic_Option_Settings
	 */
	private $settings;

	/**
	 * @var OpenID_Connect_Generic_Option_Logger
	 */
	private $logger;

	/**
	 * @var OpenID_Connect_Generic_Client_Wrapper
	 */
	private $client_wrapper;

	public function __construct( $settings, $logger, $client_wrapper ) {
		$this->settings       = $settings;
		$this->logger         = $logger;
		$this->client_wrapper = $client_wrapper;
	}

	/**
	 * @param OpenID_Connect_Generic_Option_Settings $settings
	 * @param OpenID_Connect_Generic_Option_Logger   $logger
	 * @param OpenID_Connect_Generic_Client_Wrapper  $client_wrapper
	 *
	 * @return OpenID_Connect_Generic_Magic_Link_Consumer|null
	 */
	public static function register( $settings, $logger, $client_wrapper ) {
		if ( empty( $settings->enable_magic_link ) ) {
			return null;
		}

		$instance = new self( $settings, $logger, $client_wrapper );

		// parse_request fires after init (so this registration is in time) and
		// before any output (so wp_set_auth_cookie can still send headers).
		add_action( 'parse_request', array( $instance, 'maybe_consume' ) );

		return $instance;
	}

	public function maybe_consume() {
		if ( empty( $_GET[ OpenID_Connect_Generic_Magic_Link_Rest::QUERY_PARAM ] ) ) {
			return;
		}

		$raw_nonce = sanitize_text_field( wp_unslash( $_GET[ OpenID_Connect_Generic_Magic_Link_Rest::QUERY_PARAM ] ) );

		// Cheap shape check before any DB work; the issuer always emits exactly NONCE_LENGTH alphanumeric chars.
		if ( ! preg_match( '/^[A-Za-z0-9]{' . intval( OpenID_Connect_Generic_Magic_Link_Rest::NONCE_LENGTH ) . '}$/', $raw_nonce ) ) {
			$this->fail( 'wrong_format', null );
			return;
		}

		$transient_key = OpenID_Connect_Generic_Magic_Link_Rest::TRANSIENT_PREFIX . $raw_nonce;
		$payload       = get_transient( $transient_key );

		// Single-use: delete immediately. Any concurrent consumer racing us will fail to find it.
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

		// Reuse the standard login flow: stores tokens against the new WP session,
		// runs role mapping, fires wp_login, and sets the auth cookie with an
		// expiration tied to the OIDC token lifetime.
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

		// Do not 302 to wp-login with a noisy error; the WebView caller will
		// surface its own UX. Just return a 410 so the caller can detect.
		status_header( 410 );
		nocache_headers();
		wp_die(
			esc_html__( 'This login link is invalid or has expired.', 'daggerhart-openid-connect-generic' ),
			esc_html__( 'Login link expired', 'daggerhart-openid-connect-generic' ),
			array( 'response' => 410 )
		);
	}
}
