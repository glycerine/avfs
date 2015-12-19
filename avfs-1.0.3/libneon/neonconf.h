/* 
   symbol redefines
   Copyright (C) 2005, Ralf Hoffmann <ralf@boomerangsworld.de>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#ifndef NEONCONF_H
#define NEONCONF_H

#define NEON_PREFIX 1

#ifdef NEON_PREFIX
#  define base64 AN_base64
#  define asctime_parse AN_asctime_parse
#  define rfc1036_parse AN_rfc1036_parse
#  define rfc1123_date AN_rfc1123_date
#  define rfc1123_parse AN_rfc1123_parse
#  define dav_207_create AN_dav_207_create
#  define dav_207_destroy AN_dav_207_destroy
#  define dav_207_get_current_propstat AN_dav_207_get_current_propstat
#  define dav_207_get_current_response AN_dav_207_get_current_response
#  define dav_207_ignore_unknown AN_dav_207_ignore_unknown
#  define dav_207_set_propstat_handlers AN_dav_207_set_propstat_handlers
#  define dav_207_set_response_handlers AN_dav_207_set_response_handlers
#  define dav_accept_207 AN_dav_accept_207
#  define dav_add_depth_header AN_dav_add_depth_header
#  define dav_copy AN_dav_copy
#  define dav_delete AN_dav_delete
#  define dav_mkcol AN_dav_mkcol
#  define dav_move AN_dav_move
#  define dav_simple_request AN_dav_simple_request
#  define dav_lock AN_dav_lock
#  define dav_lock_add AN_dav_lock_add
#  define dav_lock_copy AN_dav_lock_copy
#  define dav_lock_discover AN_dav_lock_discover
#  define dav_lock_find AN_dav_lock_find
#  define dav_lock_free AN_dav_lock_free
#  define dav_lock_iterate AN_dav_lock_iterate
#  define dav_lock_register AN_dav_lock_register
#  define dav_lock_remove AN_dav_lock_remove
#  define dav_lock_unregister AN_dav_lock_unregister
#  define dav_lock_using_parent AN_dav_lock_using_parent
#  define dav_lock_using_resource AN_dav_lock_using_resource
#  define dav_unlock AN_dav_unlock
#  define dav_propfind_allprop AN_dav_propfind_allprop
#  define dav_propfind_create AN_dav_propfind_create
#  define dav_propfind_current_private AN_dav_propfind_current_private
#  define dav_propfind_destroy AN_dav_propfind_destroy
#  define dav_propfind_get_parser AN_dav_propfind_get_parser
#  define dav_propfind_named AN_dav_propfind_named
#  define dav_propfind_set_complex AN_dav_propfind_set_complex
#  define dav_propfind_set_flat AN_dav_propfind_set_flat
#  define dav_proppatch AN_dav_proppatch
#  define dav_propset_iterate AN_dav_propset_iterate
#  define dav_propset_private AN_dav_propset_private
#  define dav_propset_status AN_dav_propset_status
#  define dav_propset_value AN_dav_propset_value
#  define dav_simple_propfind AN_dav_simple_propfind
#  define propstat AN_propstat
#  define hip_xml_create AN_hip_xml_create
#  define hip_xml_currentline AN_hip_xml_currentline
#  define hip_xml_destroy AN_hip_xml_destroy
#  define hip_xml_get_error AN_hip_xml_get_error
#  define hip_xml_parse AN_hip_xml_parse
#  define hip_xml_parse_v AN_hip_xml_parse_v
#  define hip_xml_push_handler AN_hip_xml_push_handler
#  define hip_xml_push_mixed_handler AN_hip_xml_push_mixed_handler
#  define hip_xml_set_error AN_hip_xml_set_error
#  define hip_xml_valid AN_hip_xml_valid
#  define http_auth_challenge AN_http_auth_challenge
#  define http_auth_create AN_http_auth_create
#  define http_auth_destroy AN_http_auth_destroy
#  define http_auth_finish AN_http_auth_finish
#  define http_auth_init AN_http_auth_init
#  define http_auth_new_request AN_http_auth_new_request
#  define http_auth_request_header AN_http_auth_request_header
#  define http_auth_response_body AN_http_auth_response_body
#  define http_auth_set_creds_cb AN_http_auth_set_creds_cb
#  define http_auth_verify_response AN_http_auth_verify_response
#  define http_content_type_handler AN_http_content_type_handler
#  define http_get AN_http_get
#  define http_get_range AN_http_get_range
#  define http_getmodtime AN_http_getmodtime
#  define http_options AN_http_options
#  define http_post AN_http_post
#  define http_put AN_http_put
#  define http_put_if_unmodified AN_http_put_if_unmodified
#  define http_read_file AN_http_read_file
#  define http_cookie_hooks AN_http_cookie_hooks
#  define http_redirect_register AN_http_redirect_register
#  define redirect_hooks AN_redirect_hooks
#  define http_accept_2xx AN_http_accept_2xx
#  define http_add_hooks AN_http_add_hooks
#  define http_add_request_header AN_http_add_request_header
#  define http_add_response_body_reader AN_http_add_response_body_reader
#  define http_add_response_header_catcher AN_http_add_response_header_catcher
#  define http_add_response_header_handler AN_http_add_response_header_handler
#  define http_duplicate_header AN_http_duplicate_header
#  define http_get_error AN_http_get_error
#  define http_get_hook_private AN_http_get_hook_private
#  define http_get_request_headers AN_http_get_request_headers
#  define http_get_scheme AN_http_get_scheme
#  define http_get_server_hostport AN_http_get_server_hostport
#  define http_get_status AN_http_get_status
#  define http_handle_numeric_header AN_http_handle_numeric_header
#  define http_print_request_header AN_http_print_request_header
#  define http_request_create AN_http_request_create
#  define http_request_destroy AN_http_request_destroy
#  define http_request_dispatch AN_http_request_dispatch
#  define http_session_create AN_http_session_create
#  define http_session_decide_proxy AN_http_session_decide_proxy
#  define http_session_destroy AN_http_session_destroy
#  define http_session_proxy AN_http_session_proxy
#  define http_session_server AN_http_session_server
#  define http_set_accept_secure_upgrade AN_http_set_accept_secure_upgrade
#  define http_set_error AN_http_set_error
#  define http_set_expect100 AN_http_set_expect100
#  define http_set_persist AN_http_set_persist
#  define http_set_proxy_auth AN_http_set_proxy_auth
#  define http_set_request_body_buffer AN_http_set_request_body_buffer
#  define http_set_request_body_stream AN_http_set_request_body_stream
#  define http_set_request_secure_upgrade AN_http_set_request_secure_upgrade
#  define http_set_secure AN_http_set_secure
#  define http_set_secure_context AN_http_set_secure_context
#  define http_set_server_auth AN_http_set_server_auth
#  define http_set_useragent AN_http_set_useragent
#  define http_version_pre_http11 AN_http_version_pre_http11
#  define http_dateparse AN_http_dateparse
#  define http_parse_statusline AN_http_parse_statusline
#  define neon_debug AN_neon_debug
#  define neon_debug_init AN_neon_debug_init
#  define neon_debug_mask AN_neon_debug_mask
#  define neon_debug_stream AN_neon_debug_stream
#  define neon_version_minimum AN_neon_version_minimum
#  define neon_version_string AN_neon_version_string
#  define md5_buffer AN_md5_buffer
#  define md5_finish_ctx AN_md5_finish_ctx
#  define md5_init_ctx AN_md5_init_ctx
#  define md5_process_block AN_md5_process_block
#  define md5_process_bytes AN_md5_process_bytes
#  define md5_read_ctx AN_md5_read_ctx
#  define md5_stream AN_md5_stream
#  define ne_calloc AN_ne_calloc
#  define ne_malloc AN_ne_malloc
#  define ne_oom_callback AN_ne_oom_callback
#  define ne_realloc AN_ne_realloc
#  define ne_strdup AN_ne_strdup
#  define ne_strndup AN_ne_strndup
#  define sock_accept AN_sock_accept
#  define sock_block AN_sock_block
#  define sock_call_progress AN_sock_call_progress
#  define sock_close AN_sock_close
#  define sock_connect AN_sock_connect
#  define sock_connect_u AN_sock_connect_u
#  define sock_create_ssl_context AN_sock_create_ssl_context
#  define sock_destroy_ssl_context AN_sock_destroy_ssl_context
#  define sock_disable_sslv2 AN_sock_disable_sslv2
#  define sock_disable_sslv3 AN_sock_disable_sslv3
#  define sock_disable_tlsv1 AN_sock_disable_tlsv1
#  define sock_exit AN_sock_exit
#  define sock_fullread AN_sock_fullread
#  define sock_fullwrite AN_sock_fullwrite
#  define sock_get_error AN_sock_get_error
#  define sock_get_fd AN_sock_get_fd
#  define sock_init AN_sock_init
#  define sock_make_secure AN_sock_make_secure
#  define sock_name_lookup AN_sock_name_lookup
#  define sock_peek AN_sock_peek
#  define sock_read AN_sock_read
#  define sock_readfile_blocked AN_sock_readfile_blocked
#  define sock_readline AN_sock_readline
#  define sock_register_notify AN_sock_register_notify
#  define sock_register_progress AN_sock_register_progress
#  define sock_send_string AN_sock_send_string
#  define sock_sendline AN_sock_sendline
#  define sock_service_lookup AN_sock_service_lookup
#  define sock_set_client_cert AN_sock_set_client_cert
#  define sock_set_key_prompt AN_sock_set_key_prompt
#  define sock_transfer AN_sock_transfer
#  define ascii_to_md5 AN_ascii_to_md5
#  define md5_to_ascii AN_md5_to_ascii
#  define ne_concat AN_ne_concat
#  define ne_utf8_encode AN_ne_utf8_encode
#  define pair_string AN_pair_string
#  define pair_string_free AN_pair_string_free
#  define sbuffer_altered AN_sbuffer_altered
#  define sbuffer_append AN_sbuffer_append
#  define sbuffer_clear AN_sbuffer_clear
#  define sbuffer_concat AN_sbuffer_concat
#  define sbuffer_create AN_sbuffer_create
#  define sbuffer_create_sized AN_sbuffer_create_sized
#  define sbuffer_data AN_sbuffer_data
#  define sbuffer_destroy AN_sbuffer_destroy
#  define sbuffer_finish AN_sbuffer_finish
#  define sbuffer_grow AN_sbuffer_grow
#  define sbuffer_size AN_sbuffer_size
#  define sbuffer_zappend AN_sbuffer_zappend
#  define shave_string AN_shave_string
#  define split_string AN_split_string
#  define split_string_c AN_split_string_c
#  define split_string_free AN_split_string_free
#  define uri_absolute AN_uri_absolute
#  define uri_abspath AN_uri_abspath
#  define uri_abspath_escape AN_uri_abspath_escape
#  define uri_childof AN_uri_childof
#  define uri_compare AN_uri_compare
#  define uri_free AN_uri_free
#  define uri_has_trailing_slash AN_uri_has_trailing_slash
#  define uri_parent AN_uri_parent
#  define uri_parse AN_uri_parse
#  define uri_unescape AN_uri_unescape
#  define fetch_resource_list AN_fetch_resource_list
#  define free_resource AN_free_resource
#  define free_resource_list AN_free_resource_list
#endif

#endif
