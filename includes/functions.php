<?php

function oidcg_get_authentication_url() {
	return \OpenID_Connect_Generic::instance()->client_wrapper->get_authentication_url();
}

function oidcg_refresh_user_claim( $user, $token_response ) {
	return \OpenID_Connect_Generic::instance()->client_wrapper->refresh_user_claim( $user, $token_response );
}
