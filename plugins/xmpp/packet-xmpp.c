#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<stdio.h>
#include<string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <epan/dissectors/packet-xml.h>

#include <plugins/xmpp/xmpp.h>
#include <plugins/xmpp/packet-xmpp.h>
#include <plugins/xmpp/xmpp-core.h>
#include <plugins/xmpp/xmpp-jingle.h>

#define XMPP_PORT 5222

static dissector_handle_t xml_handle = NULL;

int proto_xmpp = -1;


gint hf_xmpp_xmlns = -1;
gint hf_xmpp_id = -1;
gint hf_xmpp_from = -1;
gint hf_xmpp_to = -1;
gint hf_xmpp_type = -1;

gint hf_xmpp_iq = -1;

gint hf_xmpp_query = -1;
gint hf_xmpp_query_node = -1;

gint hf_xmpp_query_item = -1;
gint hf_xmpp_query_item_jid = -1;
gint hf_xmpp_query_item_name = -1;
gint hf_xmpp_query_item_subscription = -1;
gint hf_xmpp_query_item_ask = -1;
gint hf_xmpp_query_item_group = -1;
gint hf_xmpp_query_item_node = -1;
gint hf_xmpp_query_item_approved = -1;

gint hf_xmpp_query_identity = -1;
gint hf_xmpp_query_identity_category = -1;
gint hf_xmpp_query_identity_type = -1;
gint hf_xmpp_query_identity_name = -1;
gint hf_xmpp_query_identity_lang = -1;

gint hf_xmpp_query_feature = -1;

gint hf_xmpp_query_streamhost = -1;
gint hf_xmpp_query_streamhost_used = -1;
gint hf_xmpp_query_activate = -1;
gint hf_xmpp_query_udpsuccess = -1;

gint hf_xmpp_error = -1;
gint hf_xmpp_error_type = -1;
gint hf_xmpp_error_code = -1;
gint hf_xmpp_error_condition = -1;
gint hf_xmpp_error_text = -1;

gint hf_xmpp_iq_bind = -1;
gint hf_xmpp_iq_bind_jid = -1;
gint hf_xmpp_iq_bind_resource = -1;

gint hf_xmpp_iq_services = -1;

gint hf_xmpp_iq_session = -1;

gint hf_xmpp_vcard  = -1;
gint hf_xmpp_vcard_x_update = -1;

gint hf_xmpp_iq_jingle = -1;
gint hf_xmpp_iq_jingle_sid = -1;
gint hf_xmpp_iq_jingle_initiator = -1;
gint hf_xmpp_iq_jingle_responder = -1;
gint hf_xmpp_iq_jingle_action = -1;

gint hf_xmpp_iq_jingle_content = -1;
gint hf_xmpp_iq_jingle_content_creator = -1;
gint hf_xmpp_iq_jingle_content_name = -1;
gint hf_xmpp_iq_jingle_content_disposition = -1;
gint hf_xmpp_iq_jingle_content_senders = -1;

gint hf_xmpp_iq_jingle_content_description = -1;
gint hf_xmpp_iq_jingle_content_description_media = -1;
gint hf_xmpp_iq_jingle_content_description_ssrc = -1;

gint hf_xmpp_iq_jingle_cont_desc_payload = -1;
gint hf_xmpp_iq_jingle_cont_desc_payload_id = -1;
gint hf_xmpp_iq_jingle_cont_desc_payload_channels = -1;
gint hf_xmpp_iq_jingle_cont_desc_payload_clockrate = -1;
gint hf_xmpp_iq_jingle_cont_desc_payload_maxptime = -1;
gint hf_xmpp_iq_jingle_cont_desc_payload_name = -1;
gint hf_xmpp_iq_jingle_cont_desc_payload_ptime = -1;

gint hf_xmpp_iq_jingle_cont_desc_payload_param = -1;
gint hf_xmpp_iq_jingle_cont_desc_payload_param_value = -1;
gint hf_xmpp_iq_jingle_cont_desc_payload_param_name = -1;

gint hf_xmpp_iq_jingle_cont_desc_enc = -1;
gint hf_xmpp_iq_jingle_cont_desc_enc_zrtp_hash = -1;
gint hf_xmpp_iq_jingle_cont_desc_enc_crypto = -1;

gint hf_xmpp_iq_jingle_cont_desc_rtp_hdr = -1;
gint hf_xmpp_iq_jingle_cont_desc_bandwidth = -1;

gint hf_xmpp_iq_jingle_cont_trans = -1;
gint hf_xmpp_iq_jingle_cont_trans_pwd = -1;
gint hf_xmpp_iq_jingle_cont_trans_ufrag = -1;

gint hf_xmpp_iq_jingle_cont_trans_cand = -1;
gint hf_xmpp_iq_jingle_cont_trans_rem_cand = -1;

gint hf_xmpp_iq_jingle_reason = -1;
gint hf_xmpp_iq_jingle_reason_condition = -1;
gint hf_xmpp_iq_jingle_reason_text = -1;

gint hf_xmpp_iq_jingle_rtp_info = -1;

gint hf_xmpp_iq_si = -1;
gint hf_xmpp_iq_si_file = -1;

gint hf_xmpp_iq_feature_neg = -1;
gint hf_xmpp_x_data = -1;
gint hf_xmpp_x_data_field = -1;
gint hf_xmpp_x_data_field_value = -1;

gint hf_xmpp_message = -1;
gint hf_xmpp_message_chatstate = -1;

gint hf_xmpp_message_thread = -1;
gint hf_xmpp_message_thread_parent = -1;

gint hf_xmpp_message_body = -1;
gint hf_xmpp_message_subject = -1;

gint hf_xmpp_ibb_open = -1;
gint hf_xmpp_ibb_close = -1;
gint hf_xmpp_ibb_data = -1;

gint hf_xmpp_delay = -1;

gint hf_xmpp_x_event = -1;
gint hf_xmpp_x_event_condition = -1;

gint hf_xmpp_presence = -1;
gint hf_xmpp_presence_show = -1;
gint hf_xmpp_presence_status = -1;
gint hf_xmpp_presence_caps = -1;

gint hf_xmpp_auth = -1;
gint hf_xmpp_challenge = -1;
gint hf_xmpp_response = -1;
gint hf_xmpp_success = -1;
gint hf_xmpp_failure = -1;

gint hf_xmpp_muc_x = -1;
gint hf_xmpp_muc_user_x  = -1;
gint hf_xmpp_muc_user_item  = -1;
gint hf_xmpp_muc_user_invite  = -1;

gint hf_xmpp_gtalk_session = -1;
gint hf_xmpp_gtalk_session_type = -1;
gint hf_xmpp_gtalk = -1;
gint hf_xmpp_gtalk_setting = -1;
gint hf_xmpp_gtalk_nosave_x = -1;
gint hf_xmpp_gtalk_mail_mailbox = -1;
gint hf_xmpp_gtalk_mail_new_mail = -1;
gint hf_xmpp_gtalk_transport_p2p = -1;


gint hf_xmpp_conf_info = -1;
gint hf_xmpp_conf_info_sid = -1;

gint hf_xmpp_unknown = -1;
gint hf_xmpp_unknown_attr = -1;

gint hf_xmpp_out = -1;
gint hf_xmpp_in = -1;
gint hf_xmpp_response_in = -1;
gint hf_xmpp_response_to = -1;
gint hf_xmpp_jingle_session = -1;
gint hf_xmpp_ibb = -1;

gint ett_xmpp = -1;
gint ett_xmpp_iq = -1;
gint ett_xmpp_query = -1;
gint ett_xmpp_query_item = -1;
gint ett_xmpp_query_identity = -1;
gint ett_xmpp_query_feature = -1;

gint ett_xmpp_query_streamhost = -1;
gint ett_xmpp_query_streamhost_used = -1;
gint ett_xmpp_query_udpsuccess = -1;

gint ett_xmpp_iq_error = -1;
gint ett_xmpp_iq_bind = -1;
gint ett_xmpp_vcard = -1;
gint ett_xmpp_vcard_x_update = -1;

gint ett_xmpp_iq_jingle = -1;
gint ett_xmpp_iq_jingle_content = -1;
gint ett_xmpp_iq_jingle_content_description = -1;
gint ett_xmpp_iq_jingle_cont_desc_enc = -1;
gint ett_xmpp_iq_jingle_cont_desc_enc_zrtp_hash = -1;
gint ett_xmpp_iq_jingle_cont_desc_enc_crypto = -1;
gint ett_xmpp_iq_jingle_cont_desc_rtp_hdr = -1;
gint ett_xmpp_iq_jingle_cont_desc_bandwidth = -1;
gint ett_xmpp_iq_jingle_cont_desc_payload = -1;
gint ett_xmpp_iq_jingle_cont_desc_payload_param = -1;
gint ett_xmpp_iq_jingle_cont_trans = -1;
gint ett_xmpp_iq_jingle_cont_trans_cand = -1;
gint ett_xmpp_iq_jingle_cont_trans_rem_cand = -1;
gint ett_xmpp_iq_jingle_reason = -1;
gint ett_xmpp_iq_jingle_rtp_info = -1;

gint ett_xmpp_iq_si = -1;
gint ett_xmpp_iq_si_file = -1;
gint ett_xmpp_iq_si_file_range = -1;

gint ett_xmpp_iq_feature_neg = -1;
gint ett_xmpp_x_data = -1;
gint ett_xmpp_x_data_field = -1;
gint ett_xmpp_x_data_field_value = -1;

gint ett_xmpp_ibb_open = -1;
gint ett_xmpp_ibb_close = -1;
gint ett_xmpp_ibb_data = -1;

gint ett_xmpp_delay = -1;

gint ett_xmpp_x_event = -1;

gint ett_xmpp_message = -1;
gint ett_xmpp_message_thread = -1;
gint ett_xmpp_message_body = -1;
gint ett_xmpp_message_subject = -1;

gint ett_xmpp_presence = -1;
gint ett_xmpp_presence_status = -1;
gint ett_xmpp_presence_caps = -1;

gint ett_xmpp_auth = -1;
gint ett_xmpp_challenge = -1;
gint ett_xmpp_response = -1;
gint ett_xmpp_success = -1;
gint ett_xmpp_failure = -1;

gint ett_xmpp_muc_x = -1;
gint ett_xmpp_muc_hist = -1;
gint ett_xmpp_muc_user_x = -1;
gint ett_xmpp_muc_user_item = -1;
gint ett_xmpp_muc_user_invite = -1;

gint ett_xmpp_gtalk_session = -1;
gint ett_xmpp_gtalk_session_desc = -1;
gint ett_xmpp_gtalk_session_cand = -1;
gint ett_xmpp_gtalk_session_desc_payload = -1;
gint ett_xmpp_gtalk_session_reason = -1;
gint ett_xmpp_gtalk_jingleinfo_stun = -1;
gint ett_xmpp_gtalk_jingleinfo_server = -1;
gint ett_xmpp_gtalk_jingleinfo_relay = -1;
gint ett_xmpp_gtalk_jingleinfo_relay_serv = -1;
gint ett_xmpp_gtalk_setting = -1;
gint ett_xmpp_gtalk_nosave_x = -1;
gint ett_xmpp_gtalk_mail_mailbox = -1;
gint ett_xmpp_gtalk_mail_mail_info = -1;
gint ett_xmpp_gtalk_mail_senders = -1;
gint ett_xmpp_gtalk_mail_sender = -1;
gint ett_xmpp_gtalk_status_status_list = -1;
gint ett_xmpp_gtalk_transport_p2p = -1;
gint ett_xmpp_gtalk_transport_p2p_cand = -1;

gint ett_xmpp_conf_info = -1;
gint ett_xmpp_conf_desc = -1;
gint ett_xmpp_conf_state = -1;
gint ett_xmpp_conf_users = -1;
gint ett_xmpp_conf_user = -1;
gint ett_xmpp_conf_endpoint = -1;
gint ett_xmpp_conf_media = -1;

static void
dissect_xmpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    
    xml_frame_t *xml_frame;
    gboolean out_packet;

    conversation_t *conversation;
    xmpp_conv_info_t *xmpp_info;

    proto_tree *xmpp_tree = NULL;
    proto_item *xmpp_item = NULL;

    element_t *packet = NULL;

    if(check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "XMPP");

    if (check_col(pinfo->cinfo, COL_INFO))
            col_clear(pinfo->cinfo, COL_INFO);

    /*if tree == NULL then xmpp_item and xmpp_tree will also NULL*/
    xmpp_item = proto_tree_add_item(tree,proto_xmpp, tvb, 0, -1, FALSE);
    xmpp_tree = proto_item_add_subtree(xmpp_item, ett_xmpp);
    

    call_dissector(xml_handle,tvb,pinfo,xmpp_tree);
    
    if(!pinfo->private_data)
        return;

    /*data from XML dissector*/
    xml_frame = ((xml_frame_t*)pinfo->private_data)->first_child;
 
    if(!xml_frame)
        return;

    packet = xml_frame_to_element_t(xml_frame);
   


    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    if (!xmpp_info) {
        xmpp_info = se_alloc(sizeof (xmpp_conv_info_t));
        xmpp_info->req_resp = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_req_resp");
        xmpp_info->jingle_sessions = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_jingle_sessions");
        xmpp_info->ibb_sessions = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_ibb_sessions");
        xmpp_info->gtalk_sessions = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_gtalk_sessions");
        conversation_add_proto_data(conversation, proto_xmpp, (void *) xmpp_info);
    }

    
    if (pinfo->match_uint == pinfo->destport)
        out_packet = TRUE;
    else
        out_packet = FALSE;

    if (strcmp(packet->name,"iq") == 0)
    {
        xmpp_iq_reqresp_track(pinfo, packet, xmpp_info);
        xmpp_jingle_session_track(pinfo, packet, xmpp_info);
        xmpp_gtalk_session_track(pinfo, packet, xmpp_info);
    }

    if (strcmp(packet->name,"iq") == 0 || strcmp(packet->name,"message") == 0)
    {
        xmpp_ibb_session_track(pinfo, packet, xmpp_info);
    }

    if (tree) { /* we are being asked for details */
        proto_item *outin_item;

        if(out_packet)
            outin_item = proto_tree_add_boolean(xmpp_tree, hf_xmpp_out, tvb, 0, 0, TRUE);
        else
            outin_item = proto_tree_add_boolean(xmpp_tree, hf_xmpp_in, tvb, 0, 0, TRUE);
        
        PROTO_ITEM_SET_HIDDEN(outin_item);


        /*it hides tree generated by XML dissector*/
        proto_tree_hide_first_child(xmpp_tree);

        if(strcmp(packet->name,"iq") == 0)
        {
            xmpp_iq(xmpp_tree,tvb, pinfo, packet);
        } else if(strcmp(packet->name,"presence") == 0)
        {
            xmpp_presence(xmpp_tree,tvb, pinfo, packet);
        } else if(strcmp(packet->name,"message") == 0)
        {
            xmpp_message(xmpp_tree, tvb, pinfo, packet);
        } else  if(strcmp(packet->name,"auth") == 0)
        {
            xmpp_auth(xmpp_tree, tvb, pinfo, packet);
        } else  if(strcmp(packet->name,"challenge") == 0)
        {
            xmpp_challenge_response_success(xmpp_tree, tvb, pinfo, packet, hf_xmpp_challenge, ett_xmpp_challenge, "CHALLENGE");
        } else  if(strcmp(packet->name,"response") == 0)
        {
            xmpp_challenge_response_success(xmpp_tree, tvb, pinfo, packet, hf_xmpp_response, ett_xmpp_response, "RESPONSE");
        } else  if(strcmp(packet->name,"success") == 0)
        {
            xmpp_challenge_response_success(xmpp_tree, tvb, pinfo, packet, hf_xmpp_success, ett_xmpp_success, "SUCCESS");
        } else  if(strcmp(packet->name,"failure") == 0)
        {
            xmpp_failure(xmpp_tree, tvb, pinfo, packet);
        } else
        {
            proto_tree_show_first_child(xmpp_tree);
            expert_add_info_format(pinfo, xmpp_tree, PI_UNDECODED, PI_NOTE, "Unknown packet: %s", packet->name );
        }

        /*appends to COL_INFO information about src or dst*/
        if (pinfo->match_uint == pinfo->destport) {
            attr_t *to = g_hash_table_lookup(packet->attrs, "to");
            if (to)
                col_append_fstr(pinfo->cinfo, COL_INFO, "> %s ", to->value);
        } else {
            attr_t *from = g_hash_table_lookup(packet->attrs, "from");
            if (from)
                col_append_fstr(pinfo->cinfo, COL_INFO, "< %s ", from->value);
        }

        
    }
}


void
proto_register_xmpp(void) {
    static hf_register_info hf[] = {
        { &hf_xmpp_iq,
            {
                "IQ", "xmpp.iq", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq packet", HFILL
            }},
            {&hf_xmpp_xmlns,
            {
                "xmlns", "xmpp.xmlns", FT_STRING, BASE_NONE, NULL, 0x0,
                "element namespace", HFILL
            }},
            { &hf_xmpp_id,
            {
                "id", "xmpp.id", FT_STRING, BASE_NONE, NULL, 0x0,
                "packet id", HFILL
            }},
            { &hf_xmpp_type,
            {
                "type", "xmpp.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "packet type", HFILL
            }},
             { &hf_xmpp_from,
            {
                "from", "xmpp.from", FT_STRING, BASE_NONE, NULL, 0x0,
                "packet from", HFILL
            }},
             { &hf_xmpp_to,
            {
                "to", "xmpp.to", FT_STRING, BASE_NONE, NULL, 0x0,
                "packet to", HFILL
            }},
            { &hf_xmpp_query,
            {
                "QUERY", "xmpp.query", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query", HFILL
            }},
            { &hf_xmpp_query_node,
            {
                "node", "xmpp.query.node", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query node", HFILL
            }},
            { &hf_xmpp_query_item,
            {
                "ITEM", "xmpp.query.item", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query item", HFILL

            }},
            { &hf_xmpp_query_item_jid,
            {
                "jid", "xmpp.query.item.jid", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item jid", HFILL

            }},
            { &hf_xmpp_query_item_name,
            {
                "name", "xmpp.query.item.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item name", HFILL
            }},
            { &hf_xmpp_query_item_subscription,
            {
                "subscription", "xmpp.query.item.subscription", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item subscription", HFILL
            }},
            { &hf_xmpp_query_item_ask,
            {
                "ask", "xmpp.query.item.ask", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item ask", HFILL
            }},
            { &hf_xmpp_query_item_group,
            {
                "GROUP", "xmpp.query.item.group", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item group", HFILL

            }},
            { &hf_xmpp_query_item_approved,
            {
                "approved", "xmpp.query.item.approved", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item approved", HFILL

            }},
            { &hf_xmpp_query_item_node,
            {
                "node", "xmpp.query.item.node", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item node", HFILL

            }},
            { &hf_xmpp_query_identity,
            {
                "IDENTITY", "xmpp.query.identity", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query identity", HFILL

            }},
            { &hf_xmpp_query_identity_category,
            {
                "category", "xmpp.query.identity.category", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query identity category", HFILL

            }},
            { &hf_xmpp_query_identity_type,
            {
                "type", "xmpp.query.identity.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query identity type", HFILL

            }},
            { &hf_xmpp_query_identity_name,
            {
                "name", "xmpp.query.identity.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query identity name", HFILL

            }},
            { &hf_xmpp_query_identity_lang,
            {
                "lang", "xmpp.query.identity.lang", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query identity lang", HFILL

            }},
            { &hf_xmpp_query_feature,
            {
                "FEATURE", "xmpp.query.feature", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query feature", HFILL

            }},
            { &hf_xmpp_query_streamhost,
            {
                "STREAMHOST", "xmpp.query.streamhost", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query streamhost", HFILL

            }},
            { &hf_xmpp_query_streamhost_used,
            {
                "STREAMHOST-USED", "xmpp.query.streamhost-used", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query streamhost-used", HFILL

            }},
            { &hf_xmpp_query_activate,
            {
                "ACTIVATE", "xmpp.query.activate", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query activate", HFILL

            }},
            { &hf_xmpp_query_udpsuccess,
            {
                "UDPSUCCESS", "xmpp.query.udpsuccess", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query streamhost-used", HFILL

            }},
            { &hf_xmpp_error,
            {
                "ERROR", "xmpp.error", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq error", HFILL
            }},
            { &hf_xmpp_error_code,
            {
                "code", "xmpp.error.code", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza error code", HFILL

            }},
            { &hf_xmpp_error_type,
            {
                "type", "xmpp.error.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq error type", HFILL

            }},
            { &hf_xmpp_error_condition,
            {
                "CONDITION", "xmpp.error.condition", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq error condition", HFILL

            }},
            { &hf_xmpp_error_text,
            {
                "TEXT", "xmpp.error.text", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq error text", HFILL

            }},
            { &hf_xmpp_iq_bind,
            {
                "BIND", "xmpp.iq.bind", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq bind", HFILL

            }},
            { &hf_xmpp_iq_bind_jid,
            {
                "jid", "xmpp.iq.bind.jid", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq bind jid", HFILL

            }},
            { &hf_xmpp_iq_bind_resource,
            {
                "resource", "xmpp.iq.bind.resource", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq bind resource", HFILL

            }},
            { &hf_xmpp_iq_services,
            {
                "SERVICES", "xmpp.iq.services", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq services", HFILL
            }},
            { &hf_xmpp_iq_session,
            {
                "SESSION", "xmpp.iq.session", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq session", HFILL
            }},
            { &hf_xmpp_vcard,
            {
                "VCARD", "xmpp.vcard", FT_NONE, BASE_NONE, NULL, 0x0,
                "vcard-temp", HFILL
            }},
            { &hf_xmpp_vcard_x_update,
            {
                "X VCARD-UPDATE", "xmpp.vcard-update", FT_NONE, BASE_NONE, NULL, 0x0,
                "vcard-temp:x:update", HFILL
            }},
            { &hf_xmpp_iq_jingle,
            {
                "JINGLE", "xmpp.iq.jingle", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle", HFILL
            }},
            { &hf_xmpp_iq_jingle_action,
            {
                "action", "xmpp.iq.jingle.action", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle action", HFILL
            }},
            { &hf_xmpp_iq_jingle_sid,
            {
                "sid", "xmpp.iq.jingle.sid", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle sid", HFILL
            }},
            { &hf_xmpp_iq_jingle_initiator,
            {
                "initiator", "xmpp.iq.jingle.initiator", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle initiator", HFILL
            }},
            { &hf_xmpp_iq_jingle_responder,
            {
                "responder", "xmpp.iq.jingle.responder", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle responder", HFILL
            }},
            { &hf_xmpp_iq_jingle_content,
            {
                "CONTENT", "xmpp.iq.jingle.content", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content", HFILL
            }},
            { &hf_xmpp_iq_jingle_content_creator,
            {
                "creator", "xmpp.iq.jingle.content.creator", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content creator", HFILL
            }},
            { &hf_xmpp_iq_jingle_content_name,
            {
                "name", "xmpp.iq.jingle.content.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content name", HFILL
            }},
            { &hf_xmpp_iq_jingle_content_disposition,
            {
                "disposition", "xmpp.iq.jingle.content.disposition", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content disposition", HFILL
            }},
            { &hf_xmpp_iq_jingle_content_senders,
            {
                "senders", "xmpp.iq.jingle.content.senders", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content senders", HFILL
            }},
            { &hf_xmpp_iq_jingle_content_description,
            {
                "DESCRIPTION", "xmpp.iq.jingle.content.description", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content description", HFILL
            }},
            { &hf_xmpp_iq_jingle_content_description_media,
            {
                "media", "xmpp.iq.jingle.content.description.media", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description", HFILL
            }},
            { &hf_xmpp_iq_jingle_content_description_ssrc,
            {
                "ssrc", "xmpp.iq.jingle.content.description.ssrc", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description ssrc", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload,
            {
                "PAYLOAD-TYPE", "xmpp.iq.jingle.content.description.payload-type", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_id,
            {
                "id", "xmpp.iq.jingle.content.description.payload-type.id", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type id", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_channels,
            {
                "channels", "xmpp.iq.jingle.content.description.payload-type.channels", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type channels", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_clockrate,
            {
                "clockrate", "xmpp.iq.jingle.content.description.payload-type.clockrate", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type clockrate", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_maxptime,
            {
                "maxptime", "xmpp.iq.jingle.content.description.payload-type.maxptime", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type maxptime", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_name,
            {
                "name", "xmpp.iq.jingle.content.description.payload-type.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type name", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_ptime,
            {
                "ptime", "xmpp.iq.jingle.content.description.payload-type.ptime", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type ptime", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_param,
            {
                "PARAMETER", "xmpp.iq.jingle.content.description.payload-type.parameter", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type parameter", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_param_name,
            {
                "name", "xmpp.iq.jingle.content.description.payload-type.parameter.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type parameter name", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_payload_param_value,
            {
                "value", "xmpp.iq.jingle.content.description.payload-type.parameter.value", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description payload-type parameter value", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_trans,
            {
                "TRANSPORT", "xmpp.iq.jingle.content.transport", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content transport", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_trans_ufrag,
            {
                "ufrag", "xmpp.iq.jingle.content.transport.ufrag", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content transport ufrag", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_trans_pwd,
            {
                "pwd", "xmpp.iq.jingle.content.transport.pwd", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content transport pwd", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_trans_cand,
            {
                "CANDIDATE", "xmpp.iq.jingle.content.transport.candidate", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content transport candidate", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_trans_rem_cand,
            {
                "REMOTE-CANDIDATE", "xmpp.iq.jingle.content.transport.remote-candidate", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content transport remote-candidate", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_enc,
            {
                "ENCRYPTION", "xmpp.iq.jingle.content.description.encryption", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content descryption encryption", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_enc_zrtp_hash,
            {
                "ZRTP-HASH", "xmpp.iq.jingle.content.description.encryption.zrtp-hash", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content descryption encryption zrtp-hash", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_enc_crypto,
            {
                "CRYPTO", "xmpp.iq.jingle.content.description.encryption.crypto", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content descryption encryption crypto", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_bandwidth,
            {
                "BANDWIDTH", "xmpp.iq.jingle.content.description.bandwidth", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content descryption bandwidth", HFILL
            }},
            { &hf_xmpp_iq_jingle_cont_desc_rtp_hdr,
            {
                "RTP-HDREXT", "xmpp.iq.jingle.content.description.rtp-hdrext", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle content descryption rtp-hdrext", HFILL
            }},
            { &hf_xmpp_iq_jingle_reason,
            {
                "REASON", "xmpp.iq.jingle.reason", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq jingle reason", HFILL
            }},
            { &hf_xmpp_iq_jingle_reason_condition,
            {
                "CONDITION", "xmpp.iq.jingle.reason.condition", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle reason condition", HFILL
            }},
            { &hf_xmpp_iq_jingle_reason_text,
            {
                "TEXT", "xmpp.iq.jingle.reason.text", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle reason text", HFILL
            }},
            { &hf_xmpp_iq_jingle_rtp_info,
            {
                "RTP-INFO", "xmpp.iq.jingle.rtp_info", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle rtp-info(ringing, active, hold, mute, ...)", HFILL
            }},
            { &hf_xmpp_iq_si,
            {
                "SI", "xmpp.iq.si", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq si", HFILL
            }},
            { &hf_xmpp_iq_si_file,
            {
                "FILE", "xmpp.iq.si.file", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq si file", HFILL
            }},
            { &hf_xmpp_iq_feature_neg,
            {
                "FEATURE", "xmpp.feature-neg", FT_NONE, BASE_NONE, NULL, 0x0,
                "http://jabber.org/protocol/feature-neg", HFILL
            }},
            { &hf_xmpp_x_data,
            {
                "X-DATA", "xmpp.x-data", FT_NONE, BASE_NONE, NULL, 0x0,
                "jabber:x:data", HFILL
            }},
            { &hf_xmpp_x_data_field,
            {
                "FIELD", "xmpp.x-data.field", FT_NONE, BASE_NONE, NULL, 0x0,
                "jabber:x:data field", HFILL
            }},
            { &hf_xmpp_x_data_field_value,
            {
                "VALUE", "xmpp.x-data.field.value", FT_NONE, BASE_NONE, NULL, 0x0,
                "jabber:x:data field value", HFILL
            }},
            { &hf_xmpp_delay,
            {
                "DELAY", "xmpp.delay", FT_NONE, BASE_NONE, NULL, 0x0,
                "urn:xmpp:delay", HFILL
            }},
            { &hf_xmpp_x_event,
            {
                "X EVENT", "xmpp.x-event", FT_NONE, BASE_NONE, NULL, 0x0,
                "jabber:x:event", HFILL
            }},
            { &hf_xmpp_x_event_condition,
            {
                "CONDITION", "xmpp.x-event.condition", FT_STRING, BASE_NONE, NULL, 0x0,
                "jabber:x:event condition", HFILL
            }},
            { &hf_xmpp_presence,
            {
                "PRESENCE", "xmpp.presence", FT_NONE, BASE_NONE, NULL, 0x0,
                "presence packet", HFILL
            }},
            { &hf_xmpp_presence_show,
            {
                "SHOW", "xmpp.presence.show", FT_STRING, BASE_NONE, NULL, 0x0,
                "presence show", HFILL
            }},
            { &hf_xmpp_presence_status,
            {
                "STATUS", "xmpp.presence.status", FT_NONE, BASE_NONE, NULL, 0x0,
                "presence status", HFILL
            }},
            { &hf_xmpp_presence_caps,
            {
                "CAPS", "xmpp.presence.caps", FT_NONE, BASE_NONE, NULL, 0x0,
                "presence caps", HFILL
            }},
            { &hf_xmpp_message,
            {
                "MESSAGE", "xmpp.message", FT_NONE, BASE_NONE, NULL, 0x0,
                "message packet", HFILL
            }},
            { &hf_xmpp_message_chatstate,
            {
                "CHATSTATE", "xmpp.message.chatstate", FT_STRING, BASE_NONE, NULL, 0x0,
                "message chatstate", HFILL
            }},
            { &hf_xmpp_message_thread,
            {
                "THREAD", "xmpp.message.thread", FT_NONE, BASE_NONE, NULL, 0x0,
                "message thread", HFILL
            }},
            { &hf_xmpp_message_body,
            {
                "BODY", "xmpp.message.body", FT_NONE, BASE_NONE, NULL, 0x0,
                "message body", HFILL
            }},
             { &hf_xmpp_message_subject,
            {
                "SUBJECT", "xmpp.message.subject", FT_NONE, BASE_NONE, NULL, 0x0,
                "message subject", HFILL
            }},
            { &hf_xmpp_message_thread_parent,
            {
                "parent", "xmpp.message.thread.parent", FT_STRING, BASE_NONE, NULL, 0x0,
                "message thread parent", HFILL
            }},
            { &hf_xmpp_auth,
            {
                "AUTH", "xmpp.auth", FT_NONE, BASE_NONE, NULL, 0x0,
                "auth packet", HFILL
            }},
            { &hf_xmpp_challenge,
            {
                "CHALLENGE", "xmpp.challenge", FT_NONE, BASE_NONE, NULL, 0x0,
                "challenge packet", HFILL
            }},
            { &hf_xmpp_response,
            {
                "RESPONSE", "xmpp.response", FT_NONE, BASE_NONE, NULL, 0x0,
                "response packet", HFILL
            }},
            { &hf_xmpp_success,
            {
                "SUCCESS", "xmpp.success", FT_NONE, BASE_NONE, NULL, 0x0,
                "success packet", HFILL
            }},
            { &hf_xmpp_failure,
            {
                "FAILURE", "xmpp.failure", FT_NONE, BASE_NONE, NULL, 0x0,
                "failure packet", HFILL
            }},
            { &hf_xmpp_unknown,
            {
                "UNKNOWN", "xmpp.unknown", FT_STRING, BASE_NONE, NULL, 0x0,
                "unknown packet", HFILL
            }},
            { &hf_xmpp_unknown_attr,
            {
                "UNKNOWN ATTR", "xmpp.unknown_attr", FT_STRING, BASE_NONE, NULL, 0x0,
                "unknown attribute", HFILL
            }},
            { &hf_xmpp_ibb_open,
            {
                "IBB-OPEN", "xmpp.ibb.open", FT_NONE, BASE_NONE, NULL, 0x0,
                "xmpp ibb open", HFILL
            }},
            { &hf_xmpp_ibb_close,
            {
                "IBB-CLOSE", "xmpp.ibb.close", FT_NONE, BASE_NONE, NULL, 0x0,
                "xmpp ibb close", HFILL
            }},
            { &hf_xmpp_ibb_data,
            {
                "IBB-DATA", "xmpp.ibb.data", FT_NONE, BASE_NONE, NULL, 0x0,
                "xmpp ibb data", HFILL
            }},
            { &hf_xmpp_muc_x,
            {
                "X MUC", "xmpp.muc-x", FT_NONE, BASE_NONE, NULL, 0x0,
                "http://jabber.org/protocol/muc", HFILL
            }},
            { &hf_xmpp_muc_user_x,
            {
                "X MUC-USER", "xmpp.muc-user-x", FT_NONE, BASE_NONE, NULL, 0x0,
                "http://jabber.org/protocol/muc#user", HFILL
            }},
            { &hf_xmpp_muc_user_item,
            {
                "ITEM", "xmpp.muc-user-x.item", FT_NONE, BASE_NONE, NULL, 0x0,
                "muc#user item", HFILL
            }},
            { &hf_xmpp_muc_user_invite,
            {
                "INVITE", "xmpp.muc-user-x.invite", FT_NONE, BASE_NONE, NULL, 0x0,
                "muc#user invite", HFILL
            }},
            { &hf_xmpp_gtalk_session,
            {
                "GTALK-SESSION", "xmpp.gtalk.session", FT_NONE, BASE_NONE, NULL, 0x0,
                "GTalk session", HFILL
            }},
            { &hf_xmpp_gtalk_session_type,
            {
                "type", "xmpp.gtalk.session.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "GTalk session type", HFILL
            }},
            { &hf_xmpp_gtalk,
            {
                "session ID", "xmpp.gtalk", FT_STRING, BASE_NONE, NULL, 0x0,
                "GTalk session id", HFILL
            }},
            { &hf_xmpp_gtalk_setting,
            {
                "USERSETTING", "xmpp.gtalk.setting", FT_NONE, BASE_NONE, NULL, 0x0,
                "google:setting usersetting", HFILL
            }},
            { &hf_xmpp_gtalk_nosave_x,
            {
                "X-NOSAVE", "xmpp.gtalk.nosave.x", FT_NONE, BASE_NONE, NULL, 0x0,
                "google:nosave x", HFILL
            }},
            { &hf_xmpp_gtalk_mail_mailbox,
            {
                "MAILBOX", "xmpp.gtalk.mailbox", FT_NONE, BASE_NONE, NULL, 0x0,
                "google:mail:notify mailbox", HFILL
            }},
            { &hf_xmpp_gtalk_mail_new_mail,
            {
                "NEW MAIL", "xmpp.gtalk.new-mail", FT_NONE, BASE_NONE, NULL, 0x0,
                "google:mail:notify new-mail", HFILL
            }},
            { &hf_xmpp_gtalk_transport_p2p,
            {
                "TRANSPORT", "xmpp.gtalk.transport-p2p", FT_NONE, BASE_NONE, NULL, 0x0,
                "google/transport/p2p", HFILL
            }},
            { &hf_xmpp_conf_info,
            {
                "CONFERENCE INFO", "xmpp.conf-info", FT_NONE, BASE_NONE, NULL, 0x0,
                "urn:ietf:params:xml:ns:conference-info", HFILL
            }},
             { &hf_xmpp_conf_info_sid,
            {
                "sid", "xmpp.conf-info.sid", FT_STRING, BASE_NONE, NULL, 0x0,
                "urn:ietf:params:xml:ns:conference-info sid", HFILL
            }},
            { &hf_xmpp_response_in,
		{ "Response In", "xmpp.response_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		"The response to this PANA request is in this frame", HFILL }
            },
            { &hf_xmpp_response_to,
		{ "Request In", "xmpp.response_to",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		"This is a response to the PANA request in this frame", HFILL }
            },
            { &hf_xmpp_out,
            {
                "Out", "xmpp.out", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Outgoing packet", HFILL
            }},
            { &hf_xmpp_in,
            {
                "In", "xmpp.in", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Ingoing packet", HFILL
            }},
            { &hf_xmpp_ibb,
            {
                "IBB SESSION", "xmpp.ibb", FT_STRING, BASE_NONE, NULL, 0x0,
                "In-Band Bytestreams session", HFILL
            }},
            { &hf_xmpp_jingle_session,
            {
                "JINGLE SESSION", "xmpp.jingle_session", FT_STRING, BASE_NONE, NULL, 0x0,
                "Jingle SID", HFILL
            }}
    };

    static gint * ett[] = {
        &ett_xmpp,
        &ett_xmpp_iq,
        &ett_xmpp_query,
        &ett_xmpp_query_item,
        &ett_xmpp_query_identity,
        &ett_xmpp_query_feature,
        &ett_xmpp_query_streamhost,
        &ett_xmpp_query_streamhost_used,
        &ett_xmpp_query_udpsuccess,
        &ett_xmpp_iq_error,
        &ett_xmpp_iq_bind,
        &ett_xmpp_vcard,
        &ett_xmpp_vcard_x_update,
        &ett_xmpp_iq_jingle,
        &ett_xmpp_iq_jingle_content,
        &ett_xmpp_iq_jingle_content_description,
        &ett_xmpp_iq_jingle_cont_desc_payload,
        &ett_xmpp_iq_jingle_cont_desc_payload_param,
        &ett_xmpp_iq_jingle_cont_desc_enc,
        &ett_xmpp_iq_jingle_cont_desc_enc_zrtp_hash,
        &ett_xmpp_iq_jingle_cont_desc_enc_crypto,
        &ett_xmpp_iq_jingle_cont_desc_bandwidth,
        &ett_xmpp_iq_jingle_cont_desc_rtp_hdr,
        &ett_xmpp_iq_jingle_cont_trans,
        &ett_xmpp_iq_jingle_cont_trans_cand,
        &ett_xmpp_iq_jingle_cont_trans_rem_cand,
        &ett_xmpp_iq_jingle_reason,
        &ett_xmpp_iq_jingle_rtp_info,
        &ett_xmpp_iq_si,
        &ett_xmpp_iq_si_file,
        &ett_xmpp_iq_si_file_range,
        &ett_xmpp_iq_feature_neg,
        &ett_xmpp_x_data,
        &ett_xmpp_x_data_field,
        &ett_xmpp_x_data_field_value,
        &ett_xmpp_ibb_open,
        &ett_xmpp_ibb_close,
        &ett_xmpp_ibb_data,
        &ett_xmpp_delay,
        &ett_xmpp_x_event,
        &ett_xmpp_message,
        &ett_xmpp_message_thread,
        &ett_xmpp_message_subject,
        &ett_xmpp_message_body,
        &ett_xmpp_presence,
        &ett_xmpp_presence_status,
        &ett_xmpp_presence_caps,
        &ett_xmpp_auth,
        &ett_xmpp_challenge,
        &ett_xmpp_response,
        &ett_xmpp_success,
        &ett_xmpp_failure,
        &ett_xmpp_muc_x,
        &ett_xmpp_muc_hist,
        &ett_xmpp_muc_user_x,
        &ett_xmpp_muc_user_item,
        &ett_xmpp_muc_user_invite,
        &ett_xmpp_gtalk_session,
        &ett_xmpp_gtalk_session_desc,
        &ett_xmpp_gtalk_session_desc_payload,
        &ett_xmpp_gtalk_session_cand,
        &ett_xmpp_gtalk_session_reason,
        &ett_xmpp_gtalk_jingleinfo_stun,
        &ett_xmpp_gtalk_jingleinfo_server,
        &ett_xmpp_gtalk_jingleinfo_relay,
        &ett_xmpp_gtalk_jingleinfo_relay_serv,
        &ett_xmpp_gtalk_setting,
        &ett_xmpp_gtalk_nosave_x,
        &ett_xmpp_gtalk_mail_mailbox,
        &ett_xmpp_gtalk_mail_mail_info,
        &ett_xmpp_gtalk_mail_senders,
        &ett_xmpp_gtalk_mail_sender,
        &ett_xmpp_gtalk_status_status_list,
        &ett_xmpp_conf_info,
        &ett_xmpp_conf_desc,
        &ett_xmpp_conf_state,
        &ett_xmpp_conf_users,
        &ett_xmpp_conf_user,
        &ett_xmpp_conf_endpoint,
        &ett_xmpp_conf_media,
        &ett_xmpp_gtalk_transport_p2p,
        &ett_xmpp_gtalk_transport_p2p_cand,
    };

    proto_xmpp = proto_register_protocol(
            "XMPP Protocol", /* name       */
            "XMPP", /* short name */
            "xmpp" /* abbrev     */
            );
    proto_register_field_array(proto_xmpp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*to remove*/
/*
    register_dissector("xmpp2", dissect_xmpp, proto_xmpp);
*/
}

void
proto_reg_handoff_xmpp(void) {
    static dissector_handle_t xmpp_handle;

    xml_handle = find_dissector("xml");

    xmpp_handle = create_dissector_handle(dissect_xmpp, proto_xmpp);

    dissector_add_uint("tcp.port", XMPP_PORT, xmpp_handle);

}
