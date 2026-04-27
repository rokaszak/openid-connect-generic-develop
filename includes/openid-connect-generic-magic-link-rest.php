<?php
/**
 * Magic Link REST endpoint.
 *
 * @package   OpenID_Connect_Generic
 * @category  Magic Link
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_Magic_Link_Rest class.
 *
 * Exposes POST /wp-json/magic-link/v1/login. A trusted backend (typically
 * the IDP itself) authenticates with an admin Application Password and
 * posts a verified IDP token response. The plugin runs the same identity
 * resolution path as a normal OIDC callback and returns a single-use,
 * short-lived URL that, when opened in a browser, logs the resolved user
 * in via wp_set_auth_cookie.
 *
 * @package OpenID_Connect_Generic
 * @category  Magic Link
 */
class OpenID_Connect_Generic_Magic_Link_Rest {

	const ROUTE_NAMESPACE = 'magic-link/v1';
	const ROUTE           = '/login';
	const TRANSIENT_PREFIX = 'oidc_magic_link_';
	const QUERY_PARAM     = 'magic-link';
	const NONCE_LENGTH    = 64;
	const NONCE_TTL       = 60;

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
	 * @return OpenID_Connect_Generic_Magic_Link_Rest|null
	 */
	public static function register( $settings, $logger, $client_wrapper ) {
		if ( empty( $settings->enable_magic_link ) ) {
			return null;
		}

		$instance = new self( $settings, $logger, $client_wrapper );
		add_action( 'rest_api_init', array( $instance, 'register_routes' ) );

		return $instance;
	}

	public function register_routes() {
		register_rest_route(
			self::ROUTE_NAMESPACE,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_issue' ),
				'permission_callback' => array( $this, 'check_permission' ),
				'args'                => array(
					'token_response' => array(
						'required' => true,
						'type'     => 'object',
					),
				),
			)
		);
	}

	/**
	 * Only authenticated administrators may mint magic links.
	 *
	 * App Password authentication populates the current user; we then
	 * require manage_options. Any non-admin (subscriber, customer, etc.)
	 * is rejected.
	 *
	 * @return bool
	 */
	public function check_permission() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * @param WP_REST_Request $request
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_issue( $request ) {
		$token_response = $request->get_param( 'token_response' );

		if ( ! is_array( $token_response ) || empty( $token_response ) ) {
			$this->logger->log( 'magic_link_request_rejected: bad_token_response (missing or non-object)', 'magic_link' );
			return new WP_Error( 'bad_token_response', 'token_response is required and must be an object.', array( 'status' => 422 ) );
		}

		$resolved = $this->client_wrapper->resolve_user_from_token_response(
			$token_response,
			array( 'source' => 'magic_link' )
		);

		if ( is_wp_error( $resolved ) ) {
			$this->logger->log(
				'magic_link_request_rejected: ' . $resolved->get_error_code() . ' - ' . $resolved->get_error_message(),
				'magic_link'
			);
			return new WP_Error(
				'resolve_failed',
				$resolved->get_error_message(),
				array( 'status' => 422, 'code' => $resolved->get_error_code() )
			);
		}

		$nonce = wp_generate_password( self::NONCE_LENGTH, false, false );

		$payload = array(
			'user_id'          => $resolved['user']->ID,
			'token_response'   => $resolved['token_response'],
			'id_token_claim'   => $resolved['id_token_claim'],
			'user_claim'       => $resolved['user_claim'],
			'subject_identity' => $resolved['subject_identity'],
			'issued_at'        => time(),
		);

		set_transient( self::TRANSIENT_PREFIX . $nonce, $payload, self::NONCE_TTL );

		$url        = add_query_arg( self::QUERY_PARAM, $nonce, home_url( '/' ) );
		$expires_at = time() + self::NONCE_TTL;

		$this->logger->log(
			sprintf(
				'magic_link_issued: user_id=%d sub=%s expires_at=%d',
				$resolved['user']->ID,
				$resolved['subject_identity'],
				$expires_at
			),
			'magic_link'
		);

		return new WP_REST_Response(
			array(
				'url'        => $url,
				'expires_at' => $expires_at,
			),
			200
		);
	}
}
