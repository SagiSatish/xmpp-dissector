#ifndef PACKET_XMPP_H
#define	PACKET_XMPP_H

extern int proto_xmpp;

extern gint hf_xmpp_xmlns;
extern gint hf_xmpp_id;
extern gint hf_xmpp_from;
extern gint hf_xmpp_to;
extern gint hf_xmpp_type;

extern gint hf_xmpp_iq;


extern gint hf_xmpp_iq_query;
extern gint hf_xmpp_iq_query_node;

extern gint hf_xmpp_iq_query_item;
extern gint hf_xmpp_iq_query_item_jid;
extern gint hf_xmpp_iq_query_item_name;
extern gint hf_xmpp_iq_query_item_subscription;
extern gint hf_xmpp_iq_query_item_ask;
extern gint hf_xmpp_iq_query_item_group;
extern gint hf_xmpp_iq_query_item_node;
extern gint hf_xmpp_iq_query_item_approved;

extern gint hf_xmpp_iq_query_identity;
extern gint hf_xmpp_iq_query_identity_category;
extern gint hf_xmpp_iq_query_identity_type;
extern gint hf_xmpp_iq_query_identity_name;
extern gint hf_xmpp_iq_query_identity_lang;

extern gint hf_xmpp_iq_query_feature;

extern gint hf_xmpp_iq_query_streamhost;
extern gint hf_xmpp_iq_query_streamhost_used;
extern gint hf_xmpp_iq_query_activate;
extern gint hf_xmpp_iq_query_udpsuccess;

extern gint hf_xmpp_error;
extern gint hf_xmpp_error_type;
extern gint hf_xmpp_error_code;
extern gint hf_xmpp_error_condition;
extern gint hf_xmpp_error_text;

extern gint hf_xmpp_iq_bind;
extern gint hf_xmpp_iq_bind_jid;
extern gint hf_xmpp_iq_bind_resource;

extern gint hf_xmpp_iq_services;

extern gint hf_xmpp_iq_session;

extern gint hf_xmpp_vcard;
extern gint hf_xmpp_vcard_x_update;


extern gint hf_xmpp_iq_jingle;
extern gint hf_xmpp_iq_jingle_sid;
extern gint hf_xmpp_iq_jingle_initiator;
extern gint hf_xmpp_iq_jingle_responder;
extern gint hf_xmpp_iq_jingle_action;

extern gint hf_xmpp_iq_jingle_content;
extern gint hf_xmpp_iq_jingle_content_creator;
extern gint hf_xmpp_iq_jingle_content_name;
extern gint hf_xmpp_iq_jingle_content_disposition;
extern gint hf_xmpp_iq_jingle_content_senders;

extern gint hf_xmpp_iq_jingle_content_description;
extern gint hf_xmpp_iq_jingle_content_description_media;
extern gint hf_xmpp_iq_jingle_content_description_ssrc;

extern gint hf_xmpp_iq_jingle_cont_desc_payload;
extern gint hf_xmpp_iq_jingle_cont_desc_payload_id;
extern gint hf_xmpp_iq_jingle_cont_desc_payload_channels;
extern gint hf_xmpp_iq_jingle_cont_desc_payload_clockrate;
extern gint hf_xmpp_iq_jingle_cont_desc_payload_maxptime;
extern gint hf_xmpp_iq_jingle_cont_desc_payload_name;
extern gint hf_xmpp_iq_jingle_cont_desc_payload_ptime;

extern gint hf_xmpp_iq_jingle_cont_desc_payload_param;
extern gint hf_xmpp_iq_jingle_cont_desc_payload_param_value;
extern gint hf_xmpp_iq_jingle_cont_desc_payload_param_name;

extern gint hf_xmpp_iq_jingle_cont_desc_enc;
extern gint hf_xmpp_iq_jingle_cont_desc_enc_zrtp_hash;
extern gint hf_xmpp_iq_jingle_cont_desc_enc_crypto;

extern gint hf_xmpp_iq_jingle_cont_desc_rtp_hdr;
extern gint hf_xmpp_iq_jingle_cont_desc_bandwidth;

extern gint hf_xmpp_iq_jingle_cont_trans;
extern gint hf_xmpp_iq_jingle_cont_trans_pwd;
extern gint hf_xmpp_iq_jingle_cont_trans_ufrag;

extern gint hf_xmpp_iq_jingle_cont_trans_cand;
extern gint hf_xmpp_iq_jingle_cont_trans_rem_cand;

extern gint hf_xmpp_iq_jingle_reason;
extern gint hf_xmpp_iq_jingle_reason_condition;
extern gint hf_xmpp_iq_jingle_reason_text;

extern gint hf_xmpp_iq_jingle_rtp_info;

extern gint hf_xmpp_iq_si;
extern gint hf_xmpp_iq_si_file;

extern gint hf_xmpp_iq_feature_neg;
extern gint hf_xmpp_x_data;
extern gint hf_xmpp_x_data_field;
extern gint hf_xmpp_x_data_field_value;

extern gint hf_xmpp_message;
extern gint hf_xmpp_message_chatstate;

extern gint hf_xmpp_message_thread;
extern gint hf_xmpp_message_thread_parent;

extern gint hf_xmpp_message_body;
extern gint hf_xmpp_message_subject;

extern gint hf_xmpp_ibb_open;
extern gint hf_xmpp_ibb_close;
extern gint hf_xmpp_ibb_data;

extern gint hf_xmpp_delay;

extern gint hf_xmpp_x_event;
extern gint hf_xmpp_x_event_condition;

extern gint hf_xmpp_presence;
extern gint hf_xmpp_presence_show;
extern gint hf_xmpp_presence_status;
extern gint hf_xmpp_presence_caps;

extern gint hf_xmpp_auth;
extern gint hf_xmpp_challenge;
extern gint hf_xmpp_response;
extern gint hf_xmpp_success;
extern gint hf_xmpp_failure;

extern gint hf_xmpp_unknown;
extern gint hf_xmpp_unknown_attr;

extern gint hf_xmpp_req;
extern gint hf_xmpp_res;
extern gint hf_xmpp_response_in;
extern gint hf_xmpp_response_to;
extern gint hf_xmpp_jingle_session;
extern gint hf_xmpp_ibb;

extern gint ett_xmpp;
extern gint ett_xmpp_iq;
extern gint ett_xmpp_iq_query;
extern gint ett_xmpp_iq_query_item;
extern gint ett_xmpp_iq_query_identity;
extern gint ett_xmpp_iq_query_feature;

extern gint ett_xmpp_iq_query_streamhost;
extern gint ett_xmpp_iq_query_streamhost_used;
extern gint ett_xmpp_iq_query_udpsuccess;

extern gint ett_xmpp_iq_error;
extern gint ett_xmpp_iq_bind;
extern gint ett_xmpp_vcard;
extern gint ett_xmpp_vcard_x_update;

extern gint ett_xmpp_iq_jingle;
extern gint ett_xmpp_iq_jingle_content;
extern gint ett_xmpp_iq_jingle_content_description;
extern gint ett_xmpp_iq_jingle_cont_desc_enc;
extern gint ett_xmpp_iq_jingle_cont_desc_enc_zrtp_hash;
extern gint ett_xmpp_iq_jingle_cont_desc_enc_crypto;
extern gint ett_xmpp_iq_jingle_cont_desc_rtp_hdr;
extern gint ett_xmpp_iq_jingle_cont_desc_bandwidth;
extern gint ett_xmpp_iq_jingle_cont_desc_payload;
extern gint ett_xmpp_iq_jingle_cont_desc_payload_param;
extern gint ett_xmpp_iq_jingle_cont_trans;
extern gint ett_xmpp_iq_jingle_cont_trans_cand;
extern gint ett_xmpp_iq_jingle_cont_trans_rem_cand;
extern gint ett_xmpp_iq_jingle_reason;
extern gint ett_xmpp_iq_jingle_rtp_info;

extern gint ett_xmpp_iq_si;
extern gint ett_xmpp_iq_si_file;
extern gint ett_xmpp_iq_si_file_range;

extern gint ett_xmpp_iq_feature_neg;
extern gint ett_xmpp_x_data;
extern gint ett_xmpp_x_data_field;
extern gint ett_xmpp_x_data_field_value;

extern gint ett_xmpp_ibb_open;
extern gint ett_xmpp_ibb_close;
extern gint ett_xmpp_ibb_data;

extern gint ett_xmpp_delay;

extern gint ett_xmpp_x_event;

extern gint ett_xmpp_message;
extern gint ett_xmpp_message_thread;
extern gint ett_xmpp_message_body;
extern gint ett_xmpp_message_subject;

extern gint ett_xmpp_presence;
extern gint ett_xmpp_presence_status;
extern gint ett_xmpp_presence_caps;

extern gint ett_xmpp_auth;
extern gint ett_xmpp_challenge;
extern gint ett_xmpp_response;
extern gint ett_xmpp_success;
extern gint ett_xmpp_failure;


#endif	/* PACKET_XMPP_H */

