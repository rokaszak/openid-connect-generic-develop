<?php
/**
 * Bricks Builder integration.
 *
 * @package   OpenID_Connect_Generic
 * @category  Integration
 * @author    Rokas Zakarauskas <rokas@airomi.lt>
 * @copyright Rokas Zakarauskas
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_Bricks_Integration class.
 *
 * Adds custom dynamic data tags for Bricks Builder.
 *
 * @package OpenID_Connect_Generic
 * @category Integration
 */
class OpenID_Connect_Generic_Bricks_Integration {

	/**
	 * Check if Bricks Builder is active and register hooks.
	 *
	 * @return void
	 */
	public static function register() {
		// Check if Bricks is active by looking for the class.
		if ( ! class_exists( 'Bricks\Database' ) ) {
			return;
		}

		$instance = new self();

		// Step 1: Register dynamic tags in the builder.
		add_filter( 'bricks/dynamic_tags_list', array( $instance, 'register_dynamic_tags' ) );

		// Step 2: Render specific tag when called.
		add_filter( 'bricks/dynamic_data/render_tag', array( $instance, 'render_tag' ), 20, 3 );

		// Step 3: Render tags within content.
		add_filter( 'bricks/dynamic_data/render_content', array( $instance, 'render_content' ), 20, 3 );
		add_filter( 'bricks/frontend/render_data', array( $instance, 'render_content' ), 20, 2 );
	}

	/**
	 * Register custom dynamic data tags in Bricks Builder.
	 *
	 * @param array $tags Existing dynamic tags.
	 *
	 * @return array Modified tags array.
	 */
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

	/**
	 * Render individual dynamic tag.
	 *
	 * @param string $tag     The tag name with curly braces.
	 * @param mixed  $post    The post object or ID.
	 * @param string $context The context (text, link, image, etc.).
	 *
	 * @return string The rendered tag value or original tag if not matched.
	 */
	public function render_tag( $tag, $post, $context = 'text' ) {
		if ( ! is_string( $tag ) ) {
			return $tag;
		}

		// Remove curly braces.
		$clean_tag = str_replace( array( '{', '}' ), '', $tag );

		// Handle login URL.
		if ( $clean_tag === 'oidc_login_url' ) {
			return $this->get_login_url();
		}

		// Handle logout URL.
		if ( $clean_tag === 'oidc_logout_url' ) {
			return $this->get_logout_url();
		}

		return $tag;
	}

	/**
	 * Render dynamic tags within content strings.
	 *
	 * @param string $content The content that may contain dynamic tags.
	 * @param mixed  $post    The post object or ID.
	 * @param string $context The context (text, link, image, etc.).
	 *
	 * @return string The content with tags replaced.
	 */
	public function render_content( $content, $post, $context = 'text' ) {
		if ( ! is_string( $content ) ) {
			return $content;
		}

		// Check if our tags exist in the content.
		if ( strpos( $content, '{oidc_login_url}' ) !== false ) {
			$content = str_replace( '{oidc_login_url}', $this->get_login_url(), $content );
		}

		if ( strpos( $content, '{oidc_logout_url}' ) !== false ) {
			$content = str_replace( '{oidc_logout_url}', $this->get_logout_url(), $content );
		}

		return $content;
	}

	/**
	 * Get the OpenID Connect login URL.
	 *
	 * @return string The login URL.
	 */
	private function get_login_url() {
		if ( function_exists( 'oidcg_get_authentication_url' ) ) {
			return oidcg_get_authentication_url();
		}
		return '';
	}

	/**
	 * Get the OpenID Connect logout URL.
	 *
	 * @return string The logout URL.
	 */
	private function get_logout_url() {
		// Get the standard WordPress logout URL.
		$logout_url = wp_logout_url();
		
		// Apply filter to allow customization.
		return apply_filters( 'oidc_logout_url', $logout_url );
	}
}

