<?php

class OpenID_Connect_Generic_Option_Settings {


	const OPTION_NAME = 'openid_connect_generic_settings';


	private $values;


	private $default_settings;


	private $environment_settings = array(
		'client_id'                 => 'OIDC_CLIENT_ID',
		'client_secret'             => 'OIDC_CLIENT_SECRET',
		'discovery_url'             => 'OIDC_DISCOVERY_URL',
		'login_type'                => 'OIDC_LOGIN_TYPE',
		'scope'                     => 'OIDC_CLIENT_SCOPE',
		'create_if_does_not_exist'  => 'OIDC_CREATE_IF_DOES_NOT_EXIST',
		'enforce_privacy'           => 'OIDC_ENFORCE_PRIVACY',
		'link_existing_users'       => 'OIDC_LINK_EXISTING_USERS',
		'redirect_user_back'        => 'OIDC_REDIRECT_USER_BACK',
		'acr_values'                => 'OIDC_ACR_VALUES',
		'enable_logging'            => 'OIDC_ENABLE_LOGGING',
		'log_limit'                 => 'OIDC_LOG_LIMIT',
	);


	public function __construct( $default_settings = array(), $granular_defaults = true ) {
		$this->default_settings = $default_settings;
		$this->values = array();

		$this->values = (array) get_option( self::OPTION_NAME, $this->default_settings );


		foreach ( $this->environment_settings as $key => $constant ) {
			if ( defined( $constant ) ) {
				$this->__set( $key, constant( $constant ) );
			}
		}

		if ( $granular_defaults ) {
			$this->values = array_replace_recursive( $this->default_settings, $this->values );
		}
	}


	public function __get( $key ) {
		if ( isset( $this->values[ $key ] ) ) {
			return $this->values[ $key ];
		}
	}


	public function __set( $key, $value ) {
		$this->values[ $key ] = $value;
	}


	public function __isset( $key ) {
		return isset( $this->values[ $key ] );
	}


	public function __unset( $key ) {
		unset( $this->values[ $key ] );
	}


	public function get_values() {
		return $this->values;
	}


	public function get_option_name() {
		return self::OPTION_NAME;
	}


	public function save() {


		foreach ( $this->environment_settings as $key => $constant ) {
			if ( defined( $constant ) ) {
				$this->__unset( $key );
			}
		}


		delete_transient( 'oidc_discovery_document' );

		update_option( self::OPTION_NAME, $this->values );
	}
}
