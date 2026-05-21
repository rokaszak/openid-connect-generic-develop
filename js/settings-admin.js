/**
 * Airomi Connect - Admin Settings JavaScript
 *
 * Handles the role mappings repeater and image picker functionality.
 *
 * @package OpenID_Connect_Generic
 */

(function($) {
	'use strict';

	$(document).ready(function() {
		// Add new mapping row. Scoped to the repeater wrapper that contains the
		// clicked button so multiple repeaters on the same page don't collide.
		$(document).on('click', '.oidc-add-row', function(e) {
			e.preventDefault();

			var $button    = $(this);
			var $repeater  = $button.closest('.oidc-role-mappings-repeater');
			var $rows      = $repeater.find('.oidc-role-mappings-rows').first();
			var templateId = $button.data('template') || 'oidc-role-mapping-row-template';
			var template   = $('#' + templateId).html();

			if (!template) {
				return;
			}

			var nextIndex = $repeater.data('next-index');
			if (typeof nextIndex !== 'number') {
				nextIndex = $rows.children('.oidc-role-mapping-row').length;
			}
			$repeater.data('next-index', nextIndex + 1);

			var newRow = template.replace(/\{\{INDEX\}\}/g, nextIndex);
			$rows.append(newRow);
		});

		// Remove mapping row
		$(document).on('click', '.oidc-remove-row', function(e) {
			e.preventDefault();
			$(this).closest('.oidc-role-mapping-row').remove();
		});

		// Image picker functionality
		var mediaFrame;

		// Select image button
		$(document).on('click', '.oidc-select-image', function(e) {
			e.preventDefault();

			var button = $(this);
			var fieldId = button.data('field-id');
			var wrapper = button.closest('.oidc-image-picker-wrapper');
			var inputField = wrapper.find('.oidc-image-id');
			var preview = wrapper.find('.oidc-image-preview');

			// If the media frame already exists, reopen it.
			if (mediaFrame) {
				mediaFrame.open();
				return;
			}

			// Create the media frame.
			mediaFrame = wp.media({
				title: 'Select Login Button Logo',
				button: {
					text: 'Use this image'
				},
				multiple: false,
				library: {
					type: 'image'
				}
			});

			// When an image is selected, run a callback.
			mediaFrame.on('select', function() {
				var attachment = mediaFrame.state().get('selection').first().toJSON();
				
				// Set the attachment ID to the hidden input
				inputField.val(attachment.id);
				
				// Display the image preview
				preview.html('<img src="' + attachment.sizes.thumbnail.url + '" style="max-width: 150px; height: auto; display: block;">');
				
				// Show the remove button
				if (wrapper.find('.oidc-remove-image').length === 0) {
					button.after('<button type="button" class="button oidc-remove-image" data-field-id="' + fieldId + '">Remove Image</button>');
				}
			});

			// Finally, open the modal
			mediaFrame.open();
		});

		// Remove image button
		$(document).on('click', '.oidc-remove-image', function(e) {
			e.preventDefault();

			var button = $(this);
			var wrapper = button.closest('.oidc-image-picker-wrapper');
			var inputField = wrapper.find('.oidc-image-id');
			var preview = wrapper.find('.oidc-image-preview');

			// Clear the image ID
			inputField.val('');
			
			// Clear the preview
			preview.html('');
			
			// Remove the remove button
			button.remove();
		});
	});

})(jQuery);

