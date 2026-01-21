<?php
/**
 * Token storage class for OIDC session tokens.
 *
 * Stores OIDC tokens in a dedicated database table to eliminate WordPress
 * session token race conditions by using MySQL row-level locking.
 *
 * @package   OpenID_Connect_Generic
 * @category  Authentication
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_Token_Storage class.
 *
 * Handles storage and retrieval of OIDC tokens in a dedicated database table.
 *
 * @package  OpenID_Connect_Generic
 * @category Authentication
 */
class OpenID_Connect_Generic_Token_Storage {

	/**
	 * The logger object instance.
	 *
	 * @var OpenID_Connect_Generic_Option_Logger
	 */
	private $logger;

	/**
	 * Constructor.
	 *
	 * @param OpenID_Connect_Generic_Option_Logger $logger The logger object instance.
	 */
	public function __construct( OpenID_Connect_Generic_Option_Logger $logger ) {
		$this->logger = $logger;
	}

	/**
	 * Get the table name with WordPress prefix.
	 *
	 * @return string
	 */
	private function get_table_name() {
		global $wpdb;
		return $wpdb->prefix . 'oidc_session_tokens';
	}

	/**
	 * Encrypt a sensitive value using AES-256-CBC.
	 *
	 * @param string $value The value to encrypt.
	 * @return string The encrypted value with 'enc:' prefix, or original value if empty.
	 */
	private function encrypt( $value ) {
		if ( empty( $value ) ) {
			return $value;
		}

		$key = hash( 'sha256', wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), true );
		$iv = openssl_random_pseudo_bytes( 16 );
		$encrypted = openssl_encrypt( $value, 'AES-256-CBC', $key, 0, $iv );

		return 'enc:' . base64_encode( $iv . $encrypted );
	}

	/**
	 * Decrypt a value encrypted with encrypt().
	 *
	 * @param string $value The encrypted value.
	 * @return string The decrypted value, or original value if not encrypted or empty.
	 */
	private function decrypt( $value ) {
		if ( empty( $value ) || strpos( $value, 'enc:' ) !== 0 ) {
			return $value;
		}

		$key = hash( 'sha256', wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), true );
		$data = base64_decode( substr( $value, 4 ) );
		$iv = substr( $data, 0, 16 );
		$encrypted = substr( $data, 16 );

		return openssl_decrypt( $encrypted, 'AES-256-CBC', $key, 0, $iv );
	}

	/**
	 * Save token data to the database.
	 *
	 * Uses INSERT...ON DUPLICATE KEY UPDATE for atomic operations.
	 * MySQL's row-level locking handles concurrent updates automatically.
	 *
	 * @param string $wp_session_token The WordPress session token.
	 * @param int    $user_id          The WordPress user ID.
	 * @param array  $token_data       Token data array containing:
	 *                                 - access_token (string)
	 *                                 - refresh_token (string|null)
	 *                                 - id_token (string|null)
	 *                                 - expires_in (int)
	 *                                 - token_issued_at (int, defaults to time())
	 *                                 - session_expiration (int)
	 *                                 - last_userinfo_check (int, defaults to time())
	 *
	 * @return bool True on success, false on failure.
	 */
	public function save_token( $wp_session_token, $user_id, $token_data ) {
		global $wpdb;

		if ( empty( $wp_session_token ) || empty( $user_id ) ) {
			return false;
		}

		$table_name = $this->get_table_name();

		// Extract token data with defaults.
		$access_token = $this->encrypt( $token_data['access_token'] ?? '' );
		$refresh_token = $token_data['refresh_token'] ? $this->encrypt( $token_data['refresh_token'] ) : null;
		$id_token = $token_data['id_token'] ? $this->encrypt( $token_data['id_token'] ) : null;
		$expires_in = isset( $token_data['expires_in'] ) ? intval( $token_data['expires_in'] ) : 0;
		$token_issued_at = isset( $token_data['token_issued_at'] ) ? intval( $token_data['token_issued_at'] ) : time();
		$session_expiration = isset( $token_data['session_expiration'] ) ? intval( $token_data['session_expiration'] ) : 0;
		$last_userinfo_check = isset( $token_data['last_userinfo_check'] ) ? intval( $token_data['last_userinfo_check'] ) : time();

		// Use INSERT...ON DUPLICATE KEY UPDATE for atomic operation.
		$sql = $wpdb->prepare(
			"INSERT INTO {$table_name} 
			(wp_session_token, user_id, access_token, refresh_token, id_token, expires_in, token_issued_at, session_expiration, last_userinfo_check)
			VALUES (%s, %d, %s, %s, %s, %d, %d, %d, %d)
			ON DUPLICATE KEY UPDATE
			user_id = VALUES(user_id),
			access_token = VALUES(access_token),
			refresh_token = VALUES(refresh_token),
			id_token = VALUES(id_token),
			expires_in = VALUES(expires_in),
			token_issued_at = VALUES(token_issued_at),
			session_expiration = VALUES(session_expiration),
			last_userinfo_check = VALUES(last_userinfo_check)",
			$wp_session_token,
			$user_id,
			$access_token,
			$refresh_token,
			$id_token,
			$expires_in,
			$token_issued_at,
			$session_expiration,
			$last_userinfo_check
		);

		$result = $wpdb->query( $sql );

		if ( false === $result ) {
			$this->logger->log(
				array(
					'type'            => 'token_save_error',
					'wp_session_token' => $wp_session_token,
					'user_id'         => $user_id,
					'error'           => $wpdb->last_error,
				),
				'save_token',
				null
			);
			return false;
		}

		return true;
	}

	/**
	 * Get token data from the database.
	 *
	 * @param string $wp_session_token The WordPress session token.
	 *
	 * @return array|null Token data array or null if not found.
	 */
	public function get_token( $wp_session_token ) {
		global $wpdb;

		if ( empty( $wp_session_token ) ) {
			return null;
		}

		$table_name = $this->get_table_name();

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table_name} WHERE wp_session_token = %s",
				$wp_session_token
			),
			ARRAY_A
		);

		if ( empty( $row ) ) {
			return null;
		}

		// Convert database row to token response format.
		$token_data = array(
			'access_token'      => $this->decrypt( $row['access_token'] ),
			'refresh_token'     => $row['refresh_token'] ? $this->decrypt( $row['refresh_token'] ) : null,
			'id_token'          => $row['id_token'] ? $this->decrypt( $row['id_token'] ) : null,
			'expires_in'        => intval( $row['expires_in'] ),
			'time'              => intval( $row['token_issued_at'] ),
			'token_issued_at'   => intval( $row['token_issued_at'] ),
			'session_expiration' => intval( $row['session_expiration'] ),
			'last_userinfo_check' => intval( $row['last_userinfo_check'] ),
		);

		return $token_data;
	}

	/**
	 * Delete token from the database.
	 *
	 * @param string $wp_session_token The WordPress session token.
	 *
	 * @return bool True on success, false on failure.
	 */
	public function delete_token( $wp_session_token ) {
		global $wpdb;

		if ( empty( $wp_session_token ) ) {
			return false;
		}

		$table_name = $this->get_table_name();

		$result = $wpdb->delete(
			$table_name,
			array( 'wp_session_token' => $wp_session_token ),
			array( '%s' )
		);

		return false !== $result;
	}

	/**
	 * Clean up expired tokens from the database.
	 *
	 * Deletes tokens where session_expiration < current timestamp.
	 * Called by daily cron job.
	 *
	 * @return int Number of rows deleted.
	 */
	public function cleanup_expired_tokens() {
		global $wpdb;

		$table_name = $this->get_table_name();

		$deleted = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table_name} WHERE session_expiration < %d",
				time()
			)
		);

		if ( false !== $deleted && $deleted > 0 ) {
			$this->logger->log(
				array(
					'type'    => 'token_cleanup',
					'deleted' => $deleted,
				),
				'cleanup_expired_tokens',
				null
			);
		}

		return $deleted;
	}
}

