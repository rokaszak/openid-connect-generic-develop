<?php

class OpenID_Connect_Generic_Option_Logger {


	const OPTION_NAME = 'openid-connect-generic-logs';


	private $default_message_type = 'none';


	private $log_limit = 1000;


	private $logging_enabled = true;


	private $logs;


	public function __construct( $default_message_type = null, $logging_enabled = null, $log_limit = null ) {
		if ( ! is_null( $default_message_type ) ) {
			$this->default_message_type = $default_message_type;
		}
		if ( ! is_null( $logging_enabled ) ) {
			$this->logging_enabled = boolval( $logging_enabled );
		}
		if ( ! is_null( $log_limit ) ) {
			$this->log_limit = intval( $log_limit );
		}
	}


	public function log( $data, $type = null, $processing_time = null, $time = null, $user_ID = null, $request_uri = null ) {
		if ( boolval( $this->logging_enabled ) ) {
			$logs = $this->get_logs();
			$logs[] = $this->make_message( $data, $type, $processing_time, $time, $user_ID, $request_uri );
			$logs = $this->upkeep_logs( $logs );
			return $this->save_logs( $logs );
		}

		return false;
	}


	public function get_logs() {
		if ( empty( $this->logs ) ) {
			$this->logs = get_option( self::OPTION_NAME, array() );
		}



		return $this->upkeep_logs( $this->logs );
	}


	public function get_option_name() {
		return self::OPTION_NAME;
	}


	private function make_message( $data, $type, $processing_time, $time, $user_ID, $request_uri ) {

		if ( empty( $type ) ) {
			$type = $this->default_message_type;

			if ( is_array( $data ) && isset( $data['type'] ) ) {
				$type = $data['type'];
				unset( $data['type'] );
			}

			if ( is_wp_error( $data ) ) {
				$type = $data->get_error_code();
				$data = $data->get_error_message( $type );
			}
		}

		if ( empty( $request_uri ) ) {
			$request_uri = ( ! empty( $_SERVER['REQUEST_URI'] ) ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : 'Unknown';
			$request_uri = preg_replace( '/code=([^&]+)/i', 'code=', $request_uri );
		}


		$message = array(
			'type'            => $type,
			'time'            => ! empty( $time ) ? $time : time(),
			'user_ID'         => ! is_null( $user_ID ) ? $user_ID : get_current_user_id(),
			'uri'             => $request_uri,
			'data'            => $data,
			'processing_time' => $processing_time,
		);

		return $message;
	}


	private function upkeep_logs( $logs ) {
		$items_to_remove = count( $logs ) - $this->log_limit;

		if ( $items_to_remove > 0 ) {

			$logs = array_slice( $logs, $items_to_remove );
		}

		return $logs;
	}


	private function save_logs( $logs ) {

		$this->logs = $logs;
		return update_option( self::OPTION_NAME, $logs, false );
	}


	public function clear_logs() {
		$this->save_logs( array() );
	}


	public function get_logs_table( $logs = array() ) {
		if ( empty( $logs ) ) {
			$logs = $this->get_logs();
		}
		$logs = array_reverse( $logs );

		ini_set( 'xdebug.var_display_max_depth', '-1' );

		ob_start();
		?>
		<table id="logger-table" class="wp-list-table widefat fixed striped posts">
			<thead>
				<th class="col-details"><?php esc_html_e( 'Details', 'daggerhart-openid-connect-generic' ); ?></th>
				<th class="col-data"><?php esc_html_e( 'Data', 'daggerhart-openid-connect-generic' ); ?></th>
			</thead>
			<tbody>
			<?php foreach ( $logs as $log ) { ?>
				<tr>
					<td class="col-details">
						<div>
							<label><?php esc_html_e( 'Date', 'daggerhart-openid-connect-generic' ); ?></label>
							<?php print esc_html( ! empty( $log['time'] ) ? wp_date( 'Y-m-d H:i:s', $log['time'] ) : '' ); ?>
						</div>
						<div>
							<label><?php esc_html_e( 'Type', 'daggerhart-openid-connect-generic' ); ?></label>
							<?php print esc_html( ! empty( $log['type'] ) ? $log['type'] : '' ); ?>
						</div>
						<div>
							<label><?php esc_html_e( 'User', 'daggerhart-openid-connect-generic' ); ?>: </label>
							<?php print esc_html( ( get_userdata( $log['user_ID'] ) ) ? get_userdata( $log['user_ID'] )->user_login : '0' ); ?>
						</div>
						<div>
							<label><?php esc_html_e( 'URI ', 'daggerhart-openid-connect-generic' ); ?>: </label>
							<?php print esc_url( ! empty( $log['uri'] ) ? $log['uri'] : '' ); ?>
						</div>
						<div>
							<label><?php esc_html_e( 'Response&nbsp;Time&nbsp;(sec)', 'daggerhart-openid-connect-generic' ); ?></label>
							<?php print esc_html( ! empty( $log['response_time'] ) ? $log['response_time'] : '' ); ?>
						</div>
						<div>
							<label><?php esc_html_e( 'Processing&nbsp;Time&nbsp;(sec)', 'daggerhart-openid-connect-generic' ); ?></label>
							<?php print esc_html( ! empty( $log['processing_time'] ) ? number_format( $log['processing_time'], 4 ) : '' ); ?>
						</div>
					</td>
				<td class="col-data">
					<pre style="background: #f5f5f5; padding: 8px; border-radius: 3px; font-family: monospace; font-size: 12px; margin: 0; max-height: 500px; overflow-y: auto;">
						<?php
							if ( is_array( $log['data'] ) ) {

								foreach ( $log['data'] as $key => $value ) {
									echo esc_html( $key ) . ': ';
									if ( is_array( $value ) ) {
										echo esc_html( wp_json_encode( $value ) );
									} elseif ( is_object( $value ) ) {

										if ( method_exists( $value, 'to_array' ) ) {
											echo esc_html( wp_json_encode( $value->to_array() ) );
										} else {
											echo esc_html( wp_json_encode( (array) $value ) );
										}
									} else {
										echo esc_html( (string) $value );
									}
									echo "\n";
								}
							} else {

								echo esc_html( (string) $log['data'] );
							}
						?>
					</pre>
				</td>
				</tr>
			<?php } ?>
			</tbody>
		</table>
		<?php
		$output = ob_get_clean();

		return $output;
	}
}
