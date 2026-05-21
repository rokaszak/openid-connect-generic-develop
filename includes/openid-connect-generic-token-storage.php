<?php



class OpenID_Connect_Generic_Token_Storage {

	
	private $logger;

	
	public function __construct( OpenID_Connect_Generic_Option_Logger $logger ) {
		$this->logger = $logger;
	}

	
	private function get_table_name() {
		global $wpdb;
		return $wpdb->prefix . 'oidc_session_tokens';
	}

	
	private function encrypt( $value ) {
		if ( empty( $value ) ) {
			return $value;
		}

		$key = hash( 'sha256', wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), true );
		$iv = openssl_random_pseudo_bytes( 16 );
		$encrypted = openssl_encrypt( $value, 'AES-256-CBC', $key, 0, $iv );

		return 'enc:' . base64_encode( $iv . $encrypted );
	}

	
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

	
	public function save_token( $wp_session_token, $user_id, $token_data ) {
		global $wpdb;

		if ( empty( $wp_session_token ) || empty( $user_id ) ) {
			return false;
		}

		$table_name = $this->get_table_name();


		$access_token = $this->encrypt( $token_data['access_token'] ?? '' );
		$refresh_token = $token_data['refresh_token'] ? $this->encrypt( $token_data['refresh_token'] ) : null;
		$id_token = $token_data['id_token'] ? $this->encrypt( $token_data['id_token'] ) : null;
		$expires_in = isset( $token_data['expires_in'] ) ? intval( $token_data['expires_in'] ) : 0;
		$token_issued_at = isset( $token_data['token_issued_at'] ) ? intval( $token_data['token_issued_at'] ) : time();
		$session_expiration = isset( $token_data['session_expiration'] ) ? intval( $token_data['session_expiration'] ) : 0;
		$last_userinfo_check = isset( $token_data['last_userinfo_check'] ) ? intval( $token_data['last_userinfo_check'] ) : time();


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

	
	public function claim_refresh( $wp_session_token, $timeout = 30 ) {
		global $wpdb;

		if ( empty( $wp_session_token ) ) {
			return false;
		}

		$table_name = $this->get_table_name();
		$stale_before = time() - $timeout;

		$rows = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table_name} SET refresh_started_at = %d
				WHERE wp_session_token = %s
				AND (refresh_started_at IS NULL OR refresh_started_at < %d)",
				time(),
				$wp_session_token,
				$stale_before
			)
		);

		return $rows === 1;
	}

	
	public function release_refresh( $wp_session_token ) {
		global $wpdb;

		if ( empty( $wp_session_token ) ) {
			return false;
		}

		$table_name = $this->get_table_name();

		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table_name} SET refresh_started_at = NULL WHERE wp_session_token = %s",
				$wp_session_token
			)
		);

		return true;
	}

	
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

