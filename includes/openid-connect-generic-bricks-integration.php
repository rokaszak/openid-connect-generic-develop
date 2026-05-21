<?php

class OpenID_Connect_Generic_Bricks_Integration {


	public static function register() {

		if ( ! class_exists( 'Bricks\Database' ) ) {
			return;
		}

		$instance = new self();


		add_filter( 'bricks/dynamic_tags_list', array( $instance, 'register_dynamic_tags' ) );


		add_filter( 'bricks/dynamic_data/render_tag', array( $instance, 'render_tag' ), 20, 3 );


		add_filter( 'bricks/dynamic_data/render_content', array( $instance, 'render_content' ), 20, 3 );
		add_filter( 'bricks/frontend/render_data', array( $instance, 'render_content' ), 20, 2 );
	}


	public function register_dynamic_tags( $tags ) {
		$tags[] = array(
			'name'  => '{oidc_login_url}',
			'label' => 'OIDC Login URL',
			'group' => 'OpenID Connect',
		);

		$tags[] = array(
			'name'  => '{oidc_logout_url}',
			'label' => 'OIDC Logout URL',
			'group' => 'OpenID Connect',
		);

		return $tags;
	}


	public function render_tag( $tag, $post, $context = 'text' ) {
		if ( ! is_string( $tag ) ) {
			return $tag;
		}


		$clean_tag = str_replace( array( '{', '}' ), '', $tag );


		if ( $clean_tag === 'oidc_login_url' ) {
			return $this->get_login_url();
		}


		if ( $clean_tag === 'oidc_logout_url' ) {
			return $this->get_logout_url();
		}

		return $tag;
	}


	public function render_content( $content, $post, $context = 'text' ) {
		if ( ! is_string( $content ) ) {
			return $content;
		}


		if ( strpos( $content, '{oidc_login_url}' ) !== false ) {
			$content = str_replace( '{oidc_login_url}', $this->get_login_url(), $content );
		}

		if ( strpos( $content, '{oidc_logout_url}' ) !== false ) {
			$content = str_replace( '{oidc_logout_url}', $this->get_logout_url(), $content );
		}

		return $content;
	}


	private function get_login_url() {
		if ( function_exists( 'oidcg_get_authentication_url' ) ) {
			return oidcg_get_authentication_url();
		}
		return '';
	}


	private function get_logout_url() {

		$logout_url = wp_logout_url();


		return apply_filters( 'oidc_logout_url', $logout_url );
	}
}
