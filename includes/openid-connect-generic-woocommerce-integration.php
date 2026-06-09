<?php

class OpenID_Connect_Generic_WooCommerce_Integration {


	private $settings;


	private $client_wrapper;


	public function __construct( $settings, $client_wrapper ) {
		$this->settings = $settings;
		$this->client_wrapper = $client_wrapper;
	}


	public static function register( $settings, $client_wrapper ) {

		if ( ! class_exists( 'WooCommerce' ) ) {
			return null;
		}

		$integration = new self( $settings, $client_wrapper );


		if ( ! empty( $settings->enable_woocommerce_oidc ) ) {
			add_action( 'woocommerce_login_form_start', array( $integration, 'add_oidc_button_to_login' ) );
			add_action( 'woocommerce_before_customer_login_form', array( $integration, 'add_oidc_button_to_account' ) );
		}


		if ( ! empty( $settings->disable_woocommerce_password_auth ) ) {
			add_action( 'woocommerce_login_form_start', array( $integration, 'hide_woocommerce_login_form_fields' ) );
			add_filter( 'woocommerce_process_login_errors', array( $integration, 'block_woocommerce_password_login' ), 10, 3 );
		}


		if ( ! empty( $settings->disable_woocommerce_edit_account_fields ) ) {
			add_action( 'woocommerce_edit_account_form_start', array( $integration, 'add_edit_account_form_styles' ) );
			add_action( 'woocommerce_after_edit_account_form', array( $integration, 'add_sync_userinfo_button' ) );
			add_filter( 'woocommerce_save_account_details_required_fields', array( $integration, 'remove_required_account_fields' ) );
			add_filter( 'woocommerce_save_account_details_errors', array( $integration, 'prevent_account_field_saving' ), 10, 2 );
			add_action( 'template_redirect', array( $integration, 'handle_sync_userinfo' ) );
		}


		add_action( 'woocommerce_checkout_create_order', array( $integration, 'save_oidc_sub_to_order_meta' ), 10, 2 );

		return $integration;
	}


	public function save_oidc_sub_to_order_meta( $order, $data = array() ) {
		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$user_id = $order->get_customer_id();
		if ( ! $user_id ) {
			return;
		}

		$oidc_sub = get_user_meta( $user_id, 'openid-connect-generic-subject-identity', true );
		if ( ! empty( $oidc_sub ) ) {
			$order->update_meta_data( '_oidc_sub', (string) $oidc_sub );
		}
	}


	public function add_oidc_button_to_login() {
		echo wp_kses_post( $this->render_oidc_button() );
	}


	public function add_oidc_button_to_account() {

		if ( ! is_user_logged_in() ) {
			echo '<div style="text-align: center; margin-bottom: 2em;">';
			echo wp_kses_post( $this->render_oidc_button() );
			echo '</div>';
		}
	}


	public function block_woocommerce_password_login( $validation_error, $username, $password ) {

		$validation_error->add(
			'oidc_only_login',
			__( '<strong>Error:</strong> Password authentication is disabled. Please use OpenID Connect to login.', 'daggerhart-openid-connect-generic' )
		);

		return $validation_error;
	}


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


	private function render_oidc_button() {

		$button_text = ! empty( $this->settings->login_button_text )
			? $this->settings->login_button_text
			: __( 'Login with OpenID Connect', 'daggerhart-openid-connect-generic' );

		$text = apply_filters( 'openid-connect-generic-login-button-text', $button_text );
		$text = esc_html( $text );

		if ( class_exists( 'OpenID_Connect_Generic_Login_Initiator' ) ) {
			$href = OpenID_Connect_Generic_Login_Initiator::get_url();
		} else {
			$href = $this->client_wrapper->get_authentication_url();
		}
		$href = esc_url( $href );


		$logo_html = '';
		if ( ! empty( $this->settings->login_button_image_id ) ) {
			$image_id = intval( $this->settings->login_button_image_id );


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


	public function add_edit_account_form_styles() {
		?>
		<style type="text/css">
			/* Hide password fieldset */
			.woocommerce-EditAccountForm fieldset {
				display: none !important;
			}

			/* Make email, first name, and last name fields read-only */
			.woocommerce-EditAccountForm input#account_email,
			.woocommerce-EditAccountForm input#account_first_name,
			.woocommerce-EditAccountForm input#account_last_name {
				background-color: #f5f5f5 !important;
				cursor: not-allowed !important;
				pointer-events: none !important;
			}

			/* Keep display name editable - no restrictions */
		</style>
		<?php
	}


	public function remove_required_account_fields( $required_fields ) {
		unset( $required_fields['account_password'] );
		unset( $required_fields['account_password_2'] );

		return $required_fields;
	}


	public function prevent_account_field_saving( $errors, $user ) {


		if ( isset( $_POST['account_email'] ) ) {
			$current_email = $user->user_email;
			$new_email = sanitize_email( wp_unslash( $_POST['account_email'] ) );
			if ( $new_email !== $current_email ) {
				$errors->add(
					'oidc_email_change_blocked',
					__( 'Email cannot be changed. Please use the "Sync User Info" button to update your email from OpenID Connect.', 'daggerhart-openid-connect-generic' )
				);
			}
		}

		if ( isset( $_POST['account_first_name'] ) ) {
			$current_first_name = get_user_meta( $user->ID, 'first_name', true );
			$new_first_name = sanitize_text_field( wp_unslash( $_POST['account_first_name'] ) );
			if ( $new_first_name !== $current_first_name ) {
				$errors->add(
					'oidc_first_name_change_blocked',
					__( 'First name cannot be changed. Please use the "Sync User Info" button to update your name from OpenID Connect.', 'daggerhart-openid-connect-generic' )
				);
			}
		}

		if ( isset( $_POST['account_last_name'] ) ) {
			$current_last_name = get_user_meta( $user->ID, 'last_name', true );
			$new_last_name = sanitize_text_field( wp_unslash( $_POST['account_last_name'] ) );
			if ( $new_last_name !== $current_last_name ) {
				$errors->add(
					'oidc_last_name_change_blocked',
					__( 'Last name cannot be changed. Please use the "Sync User Info" button to update your name from OpenID Connect.', 'daggerhart-openid-connect-generic' )
				);
			}
		}

		if ( isset( $_POST['password_1'] ) && ! empty( $_POST['password_1'] ) ) {
			$errors->add(
				'oidc_password_change_blocked',
				__( 'Password cannot be changed. Password management is handled through OpenID Connect.', 'daggerhart-openid-connect-generic' )
			);
		}
		return $errors;
	}


	public function add_sync_userinfo_button() {

		$button_text = ! empty( $this->settings->sync_userinfo_button_text )
			? $this->settings->sync_userinfo_button_text
			: __( 'Sync User Info', 'daggerhart-openid-connect-generic' );

		$button_text = esc_html( $button_text );


		$sync_url = wp_nonce_url(
			add_query_arg( 'oidc_sync_userinfo', '1', wc_get_page_permalink( 'myaccount' ) . 'edit-account/' ),
			'oidc_sync_userinfo',
			'oidc_sync_nonce'
		);


		?>
		<p class="woocommerce-form-row form-row">
			<a href="<?php echo esc_url( $sync_url ); ?>" class="woocommerce-Button button" style="margin-top: 2rem;">
				<?php echo wp_kses_post( $button_text ); ?>
			</a>
		</p>
		<?php
	}


	public function handle_sync_userinfo() {

		if ( ! isset( $_GET['oidc_sync_userinfo'] ) ) {
			return;
		}

		$logger = $this->client_wrapper->get_logger();


		$logger->log(
			array(
				'message' => 'WooCommerce sync userinfo action started',
			),
			'woocommerce_sync_start'
		);


		if ( ! is_user_logged_in() ) {
			$logger->log(
				array(
					'message' => 'Sync userinfo failed: User not logged in',
				),
				'woocommerce_sync_error'
			);
			wc_add_notice( __( 'You must be logged in to sync user information.', 'daggerhart-openid-connect-generic' ), 'error' );
			wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
			exit;
		}


		if ( ! isset( $_GET['oidc_sync_nonce'] ) || ! wp_verify_nonce( wp_unslash( $_GET['oidc_sync_nonce'] ), 'oidc_sync_userinfo' ) ) {
			$logger->log(
				array(
					'message' => 'Sync userinfo failed: Security check failed (invalid nonce)',
				),
				'woocommerce_sync_error'
			);
			wc_add_notice( __( 'Security check failed. Please try again.', 'daggerhart-openid-connect-generic' ), 'error' );
			wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
			exit;
		}

		$user_id = get_current_user_id();
		$user = get_user_by( 'id', $user_id );

		if ( ! $user ) {
			$logger->log(
				array(
					'message' => sprintf( 'Sync userinfo failed: User not found (ID: %d)', $user_id ),
				),
				'woocommerce_sync_error'
			);
			wc_add_notice( __( 'User not found.', 'daggerhart-openid-connect-generic' ), 'error' );
			wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
			exit;
		}


		$token_response = $this->client_wrapper->get_current_user_token_response( $user_id );

		if ( empty( $token_response ) || empty( $token_response['access_token'] ) ) {
			$logger->log(
				array(
					'message' => sprintf( 'Sync userinfo failed: No valid OpenID Connect session found for user ID %d', $user_id ),
				),
				'woocommerce_sync_error'
			);
			wc_add_notice(
				__( 'Unable to sync user info. No valid OpenID Connect session found. Please log in again using OpenID Connect.', 'daggerhart-openid-connect-generic' ),
				'error'
			);
			wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
			exit;
		}


		$client = $this->client_wrapper->get_client();


		$userinfo_result = $client->request_userinfo( $token_response['access_token'] );

		if ( is_wp_error( $userinfo_result ) ) {
			$error_message = $userinfo_result->get_error_message();
			$logger->log(
				array(
					'message' => sprintf( 'Sync userinfo failed: Failed to fetch userinfo from OIDC provider. Error: %s', $error_message ),
				),
				'woocommerce_sync_error'
			);
			wc_add_notice(
				__( 'Failed to fetch user information from OpenID Connect provider. Please try again later.', 'daggerhart-openid-connect-generic' ),
				'error'
			);
			wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
			exit;
		}


		$user_claim = json_decode( wp_remote_retrieve_body( $userinfo_result ), true );

		if ( empty( $user_claim ) || ! is_array( $user_claim ) ) {
			$logger->log(
				array(
					'message' => 'Sync userinfo failed: Invalid response from OpenID Connect provider (empty or not an array)',
				),
				'woocommerce_sync_error'
			);
			wc_add_notice(
				__( 'Invalid response from OpenID Connect provider.', 'daggerhart-openid-connect-generic' ),
				'error'
			);
			wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
			exit;
		}


		$current_email = $user->user_email;
		$current_first_name = get_user_meta( $user_id, 'first_name', true );
		$current_last_name = get_user_meta( $user_id, 'last_name', true );

		$email = isset( $user_claim['email'] ) ? sanitize_email( $user_claim['email'] ) : '';
		$first_name = isset( $user_claim['given_name'] ) ? sanitize_text_field( $user_claim['given_name'] ) : '';
		$last_name = isset( $user_claim['family_name'] ) ? sanitize_text_field( $user_claim['family_name'] ) : '';


		if ( ! empty( $this->settings->email_format ) ) {
			$formatted_email = $this->format_string_with_claim( $this->settings->email_format, $user_claim, false );
			if ( ! empty( $formatted_email ) && ! is_wp_error( $formatted_email ) ) {
				$email = sanitize_email( $formatted_email );
			}
		}


		$user_data = array(
			'ID' => $user_id,
			'first_name' => $first_name,
			'last_name' => $last_name,
		);

		if ( ! empty( $email ) && is_email( $email ) ) {

			$email_exists = email_exists( $email );
			if ( $email_exists && $email_exists !== $user_id ) {
				$logger->log(
					array(
						'message' => sprintf( 'Sync userinfo failed: Email address %s is already in use by another account (user ID: %d)', $email, $email_exists ),
					),
					'woocommerce_sync_error'
				);
				wc_add_notice(
					__( 'The email address from OpenID Connect is already in use by another account.', 'daggerhart-openid-connect-generic' ),
					'error'
				);
				wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
				exit;
			}
			$user_data['user_email'] = $email;
		}

		$update_result = wp_update_user( $user_data );

		if ( is_wp_error( $update_result ) ) {
			$error_message = $update_result->get_error_message();
			$logger->log(
				array(
					'message' => sprintf( 'Sync userinfo failed: Failed to update user information. Error: %s', $error_message ),
				),
				'woocommerce_sync_error'
			);
			wc_add_notice(
				sprintf(
					/* translators: %s: Error message */
					__( 'Failed to update user information: %s', 'daggerhart-openid-connect-generic' ),
					$error_message
				),
				'error'
			);
			wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
			exit;
		}


		clean_user_cache( $user_id );


		$changed_fields = array();
		if ( ! empty( $email ) && $email !== $current_email ) {
			$changed_fields[] = sprintf( 'email: %s -> %s', $current_email, $email );
		}
		if ( $first_name !== $current_first_name ) {
			$changed_fields[] = sprintf( 'first_name: %s -> %s', $current_first_name ?: '(empty)', $first_name ?: '(empty)' );
		}
		if ( $last_name !== $current_last_name ) {
			$changed_fields[] = sprintf( 'last_name: %s -> %s', $current_last_name ?: '(empty)', $last_name ?: '(empty)' );
		}


		if ( ! empty( $changed_fields ) ) {
			$logger->log(
				array(
					'message' => sprintf(
						'Sync userinfo successful for user ID %d. Changed fields: %s',
						$user_id,
						implode( ', ', $changed_fields )
					),
				),
				'woocommerce_sync_success'
			);
		} else {
			$logger->log(
				array(
					'message' => sprintf( 'Sync userinfo completed for user ID %d. No fields changed (already up to date).', $user_id ),
				),
				'woocommerce_sync_success'
			);
		}


		$success_message = ! empty( $this->settings->sync_userinfo_success_message )
			? $this->settings->sync_userinfo_success_message
			: __( 'User information synced successfully from OpenID Connect.', 'daggerhart-openid-connect-generic' );
		wc_add_notice( esc_html( $success_message ), 'success' );


		wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) . 'edit-account/' );
		exit;
	}


	private function format_string_with_claim( $format, $user_claim, $error_on_missing_key = false ) {
		$matches = null;
		$string = '';
		$info = '';
		$i = 0;

		if ( preg_match_all( '/\{[^}]*\}/u', $format, $matches, PREG_OFFSET_CAPTURE ) ) {
			foreach ( $matches[0] as $match ) {
				$key = substr( $match[0], 1, -1 );
				$string .= substr( $format, $i, $match[1] - $i );

				$value = $this->get_claim_value( $key, $user_claim );
				if ( null === $value ) {
					if ( $error_on_missing_key ) {
						return new WP_Error(
							'incomplete-user-claim',
							__( 'User claim incomplete.', 'daggerhart-openid-connect-generic' ),
							array(
								'message' => 'Unable to find key: ' . $key . ' in user_claim',
								'user_claim' => $user_claim,
								'format' => $format,
							)
						);
					}
				} else {
					$string .= $value;
				}

				$i = $match[1] + strlen( $match[0] );
			}
		}

		$string .= substr( $format, $i );
		return $string;
	}


	private function get_claim_value( $key, $user_claim ) {
		if ( empty( $key ) || ! is_array( $user_claim ) ) {
			return null;
		}


		if ( strpos( $key, '.' ) !== false ) {
			$keys = explode( '.', $key );
			$value = $user_claim;
			foreach ( $keys as $k ) {
				if ( ! isset( $value[ $k ] ) ) {
					return null;
				}
				$value = $value[ $k ];
			}
			return $value;
		}

		return isset( $user_claim[ $key ] ) ? $user_claim[ $key ] : null;
	}
}
