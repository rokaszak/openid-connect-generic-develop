

(function($) {
	'use strict';

	$(document).ready(function() {


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


		$(document).on('click', '.oidc-remove-row', function(e) {
			e.preventDefault();
			$(this).closest('.oidc-role-mapping-row').remove();
		});


		var mediaFrame;


		$(document).on('click', '.oidc-select-image', function(e) {
			e.preventDefault();

			var button = $(this);
			var fieldId = button.data('field-id');
			var wrapper = button.closest('.oidc-image-picker-wrapper');
			var inputField = wrapper.find('.oidc-image-id');
			var preview = wrapper.find('.oidc-image-preview');


			if (mediaFrame) {
				mediaFrame.open();
				return;
			}


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


			mediaFrame.on('select', function() {
				var attachment = mediaFrame.state().get('selection').first().toJSON();
				

				inputField.val(attachment.id);
				

				preview.html('<img src="' + attachment.sizes.thumbnail.url + '" style="max-width: 150px; height: auto; display: block;">');
				

				if (wrapper.find('.oidc-remove-image').length === 0) {
					button.after('<button type="button" class="button oidc-remove-image" data-field-id="' + fieldId + '">Remove Image</button>');
				}
			});


			mediaFrame.open();
		});


		$(document).on('click', '.oidc-remove-image', function(e) {
			e.preventDefault();

			var button = $(this);
			var wrapper = button.closest('.oidc-image-picker-wrapper');
			var inputField = wrapper.find('.oidc-image-id');
			var preview = wrapper.find('.oidc-image-preview');


			inputField.val('');
			

			preview.html('');
			

			button.remove();
		});
	});

})(jQuery);

