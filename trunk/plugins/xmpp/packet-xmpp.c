#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<stdio.h>
#include<string.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/expert.h>

#include <epan/dissectors/packet-xml.h>

#include <plugins/xmpp/xmpp.h>

#include <glib.h>

#define XMPP_PORT 5222

static int proto_xmpp = -1;

static gint hf_xmpp_xmlns = -1;

static gint hf_xmpp_iq = -1;
static gint hf_xmpp_iq_id = -1;
static gint hf_xmpp_iq_type = -1;
static gint hf_xmpp_iq_from = -1;
static gint hf_xmpp_iq_to = -1;

static gint hf_xmpp_iq_query = -1;
static gint hf_xmpp_iq_query_xmlns = -1;
static gint hf_xmpp_iq_query_node = -1;

static gint hf_xmpp_iq_query_item = -1;
static gint hf_xmpp_iq_query_item_jid = -1;
static gint hf_xmpp_iq_query_item_name = -1;
static gint hf_xmpp_iq_query_item_subscription = -1;
static gint hf_xmpp_iq_query_item_ask = -1;
static gint hf_xmpp_iq_query_item_group = -1;
static gint hf_xmpp_iq_query_item_node = -1;
static gint hf_xmpp_iq_query_item_approved = -1;

static gint hf_xmpp_iq_query_identity = -1;
static gint hf_xmpp_iq_query_identity_category = -1;
static gint hf_xmpp_iq_query_identity_type = -1;
static gint hf_xmpp_iq_query_identity_name = -1;
static gint hf_xmpp_iq_query_identity_lang = -1;

static gint hf_xmpp_iq_query_feature = -1;

static gint hf_xmpp_iq_error = -1;
static gint hf_xmpp_iq_error_type = -1;
static gint hf_xmpp_iq_error_code = -1;
static gint hf_xmpp_iq_error_condition = -1;
static gint hf_xmpp_iq_error_text = -1;

static gint hf_xmpp_iq_bind = -1;
static gint hf_xmpp_iq_bind_jid = -1;
static gint hf_xmpp_iq_bind_resource = -1;

static gint hf_xmpp_iq_services = -1;

static gint hf_xmpp_iq_session = -1;

static gint hf_xmpp_iq_vcard  = -1;
static gint hf_xmpp_iq_vcard_content = -1;

static gint hf_xmpp_iq_jingle = -1;
static gint hf_xmpp_iq_jingle_sid = -1;
static gint hf_xmpp_iq_jingle_initiator = -1;
static gint hf_xmpp_iq_jingle_responder = -1;
static gint hf_xmpp_iq_jingle_action = -1;

static gint hf_xmpp_iq_jingle_content = -1;
static gint hf_xmpp_iq_jingle_content_creator = -1;
static gint hf_xmpp_iq_jingle_content_name = -1;
static gint hf_xmpp_iq_jingle_content_disposition = -1;
static gint hf_xmpp_iq_jingle_content_senders = -1;

static gint hf_xmpp_iq_jingle_content_description = -1;
static gint hf_xmpp_iq_jingle_content_description_xmlns = -1;
static gint hf_xmpp_iq_jingle_content_description_media = -1;
static gint hf_xmpp_iq_jingle_content_description_ssrc = -1;

static gint hf_xmpp_iq_jingle_cont_desc_payload = -1;
static gint hf_xmpp_iq_jingle_cont_desc_payload_id = -1;
static gint hf_xmpp_iq_jingle_cont_desc_payload_channels = -1;
static gint hf_xmpp_iq_jingle_cont_desc_payload_clockrate = -1;
static gint hf_xmpp_iq_jingle_cont_desc_payload_maxptime = -1;
static gint hf_xmpp_iq_jingle_cont_desc_payload_name = -1;
static gint hf_xmpp_iq_jingle_cont_desc_payload_ptime = -1;

static gint hf_xmpp_iq_jingle_cont_desc_payload_param = -1;
static gint hf_xmpp_iq_jingle_cont_desc_payload_param_value = -1;
static gint hf_xmpp_iq_jingle_cont_desc_payload_param_name = -1;

static gint hf_xmpp_iq_jingle_cont_desc_enc = -1;
static gint hf_xmpp_iq_jingle_cont_desc_enc_zrtp_hash = -1;
static gint hf_xmpp_iq_jingle_cont_desc_enc_crypto = -1;

static gint hf_xmpp_iq_jingle_cont_desc_rtp_hdr = -1;
static gint hf_xmpp_iq_jingle_cont_desc_bandwidth = -1;

static gint hf_xmpp_iq_jingle_cont_trans = -1;
static gint hf_xmpp_iq_jingle_cont_trans_pwd = -1;
static gint hf_xmpp_iq_jingle_cont_trans_ufrag = -1;

static gint hf_xmpp_iq_jingle_cont_trans_cand = -1;
static gint hf_xmpp_iq_jingle_cont_trans_rem_cand = -1;

static gint hf_xmpp_iq_jingle_reason = -1;
static gint hf_xmpp_iq_jingle_reason_condition = -1;
static gint hf_xmpp_iq_jingle_reason_text = -1;

static gint hf_xmpp_iq_jingle_rtp_info = -1;

static gint hf_xmpp_message = -1;
static gint hf_xmpp_message_id = -1;
static gint hf_xmpp_message_type = -1;
static gint hf_xmpp_message_chatstate = -1;

static gint hf_xmpp_message_thread = -1;
static gint hf_xmpp_message_thread_parent = -1;

static gint hf_xmpp_message_body = -1;
static gint hf_xmpp_message_subject = -1;

static gint hf_xmpp_ibb_open = -1;
static gint hf_xmpp_ibb_close = -1;
static gint hf_xmpp_ibb_data = -1;

static gint hf_xmpp_presence = -1;
static gint hf_xmpp_presence_id = -1;
static gint hf_xmpp_presence_type = -1;
static gint hf_xmpp_presence_show = -1;
static gint hf_xmpp_presence_status = -1;
static gint hf_xmpp_presence_caps = -1;

static gint hf_xmpp_auth = -1;
static gint hf_xmpp_auth_mechanism = -1;
static gint hf_xmpp_auth_content = -1;
static gint hf_xmpp_challenge = -1;
static gint hf_xmpp_challenge_content = -1;
static gint hf_xmpp_response = -1;
static gint hf_xmpp_response_content = -1;
static gint hf_xmpp_success = -1;
static gint hf_xmpp_success_content = -1;

static gint hf_xmpp_unknown = -1;

static gint hf_xmpp_req = -1;
static gint hf_xmpp_res = -1;
static gint hf_xmpp_response_in = -1;
static gint hf_xmpp_response_to = -1;
static gint hf_xmpp_jingle_session = -1;
static gint hf_xmpp_ibb = -1;

static gint ett_xmpp = -1;
static gint ett_xmpp_iq = -1;
static gint ett_xmpp_iq_query = -1;
static gint ett_xmpp_iq_query_item = -1;
static gint ett_xmpp_iq_query_identity = -1;
static gint ett_xmpp_iq_query_feature = -1;

static gint ett_xmpp_iq_error = -1;
static gint ett_xmpp_iq_bind = -1;
static gint ett_xmpp_iq_vcard = -1;

static gint ett_xmpp_iq_jingle = -1;
static gint ett_xmpp_iq_jingle_content = -1;
static gint ett_xmpp_iq_jingle_content_description = -1;
static gint ett_xmpp_iq_jingle_cont_desc_enc = -1;
static gint ett_xmpp_iq_jingle_cont_desc_enc_zrtp_hash = -1;
static gint ett_xmpp_iq_jingle_cont_desc_enc_crypto = -1;
static gint ett_xmpp_iq_jingle_cont_desc_rtp_hdr = -1;
static gint ett_xmpp_iq_jingle_cont_desc_bandwidth = -1;
static gint ett_xmpp_iq_jingle_cont_desc_payload = -1;
static gint ett_xmpp_iq_jingle_cont_desc_payload_param = -1;
static gint ett_xmpp_iq_jingle_cont_trans = -1;
static gint ett_xmpp_iq_jingle_cont_trans_cand = -1;
static gint ett_xmpp_iq_jingle_cont_trans_rem_cand = -1;
static gint ett_xmpp_iq_jingle_reason = -1;
static gint ett_xmpp_iq_jingle_rtp_info = -1;

static gint ett_xmpp_ibb_open = -1;
static gint ett_xmpp_ibb_close = -1;
static gint ett_xmpp_ibb_data = -1;

static gint ett_xmpp_message = -1;
static gint ett_xmpp_message_thread = -1;
static gint ett_xmpp_message_body = -1;
static gint ett_xmpp_message_subject = -1;

static gint ett_xmpp_presence = -1;
static gint ett_xmpp_presence_status = -1;
static gint ett_xmpp_presence_caps = -1;

static gint ett_xmpp_auth = -1;
static gint ett_xmpp_challenge = -1;
static gint ett_xmpp_response = -1;
static gint ett_xmpp_success = -1;

static dissector_handle_t xml_handle = NULL;


static xmpp_transaction_t* xmpp_iq_reqresp_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);
static void xmpp_jingle_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);

static void xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_iq_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_iq_query_item(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_iq_query_identity(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_iq_query_feature(proto_tree *tree, tvbuff_t *tvb, element_t *element);

static void xmpp_iq_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_iq_error_text(proto_tree *tree, tvbuff_t *tvb, element_t *element);

static void xmpp_iq_bind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_iq_services(proto_tree *tree, tvbuff_t *tvb, element_t *element);
static void xmpp_iq_session(proto_tree *tree, tvbuff_t *tvb, element_t *element);
static void xmpp_iq_vcard(proto_tree *tree, tvbuff_t *tvb, element_t *element);

static void xmpp_iq_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_iq_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

static void xmpp_iq_jingle_content_description(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_payload_param(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);

static void xmpp_iq_jingle_cont_desc_enc(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_enc_zrtp_hash(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_enc_crypto(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);

static void xmpp_iq_jingle_cont_desc_bandwidth(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_rtp_hdrext(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);

static void xmpp_iq_jingle_cont_trans(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_iq_jingle_cont_trans_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_cont_trans_remote_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

static void xmpp_iq_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_rtp_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

static void xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_presence_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_presence_caps(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_message_thread(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_message_body(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_message_subject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_ibb_open(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_ibb_close(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_ibb_data(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, element_t *packet, gint hf, gint ett,
    gint hf_content, const char *col_info);

static void xmpp_unknown(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static xmpp_transaction_t*
xmpp_iq_reqresp_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    xmpp_transaction_t *xmpp_trans = NULL;

    attr_t *attr_id;
    char *id;

    attr_id = g_hash_table_lookup(packet->attrs, "id");
    id = ep_strdup(attr_id->value);



    if (!pinfo->fd->flags.visited) {
        xmpp_trans = se_tree_lookup_string(xmpp_info->req_resp, id, EMEM_TREE_STRING_NOCASE);
        if (xmpp_trans) {
            xmpp_trans->resp_frame = pinfo->fd->num;

        } else {
            char *se_id = se_strdup(id);

            xmpp_trans = se_alloc(sizeof (xmpp_transaction_t));
            xmpp_trans->req_frame = pinfo->fd->num;
            xmpp_trans->resp_frame = 0;

            se_tree_insert_string(xmpp_info->req_resp, se_id, (void *) xmpp_trans, EMEM_TREE_STRING_NOCASE);

        }

    } else {
        xmpp_trans = se_tree_lookup_string(xmpp_info->req_resp, id, EMEM_TREE_STRING_NOCASE);
    }

    //create fake xmpp transaction
    if (!xmpp_trans) {
        xmpp_trans = se_alloc(sizeof (xmpp_transaction_t));
        xmpp_trans->resp_frame = 0;
        xmpp_trans->req_frame = 0;
    }

    return xmpp_trans;
}

static void
xmpp_jingle_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    element_t *jingle_packet;
    GList *jingle_packet_l;
    
    jingle_packet_l = find_element_by_name(packet,"jingle");
    jingle_packet = jingle_packet_l?jingle_packet_l->data:NULL;

    if (jingle_packet && !pinfo->fd->flags.visited) {
        attr_t *attr_id;
        attr_t *attr_sid;

        char *se_id;
        char *se_sid;


        attr_id = g_hash_table_lookup(packet->attrs, "id");
        se_id = se_strdup(attr_id->value);

        attr_sid = g_hash_table_lookup(jingle_packet->attrs, "sid");
        se_sid = se_strdup(attr_sid->value);

        se_tree_insert_string(xmpp_info->jingle_sessions, se_id, (void*) se_sid, EMEM_TREE_STRING_NOCASE);
    }
}

static void
xmpp_ibb_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    element_t *ibb_packet;
    GList *ibb_packet_l;

    if(strcmp(packet->name, "message") == 0)
    {
        ibb_packet_l = find_element_by_name(packet,"data");
        ibb_packet = ibb_packet_l?ibb_packet_l->data:NULL;
        
    } else if(strcmp(packet->name, "iq") == 0)
    {
        ibb_packet_l = find_element_by_name(packet,"open");
        
        if(!ibb_packet_l)
            ibb_packet_l = find_element_by_name(packet,"close");
         if(!ibb_packet_l)
            ibb_packet_l = find_element_by_name(packet,"data");

        ibb_packet = ibb_packet_l?ibb_packet_l->data:NULL;
    }

    if (ibb_packet && !pinfo->fd->flags.visited) {
        attr_t *attr_id;
        attr_t *attr_sid;

        char *se_id;
        char *se_sid;


        attr_id = g_hash_table_lookup(packet->attrs, "id");
        attr_sid = g_hash_table_lookup(ibb_packet->attrs, "sid");
        if(attr_id && attr_sid)
        {
            se_id = se_strdup(attr_id->value);
            se_sid = se_strdup(attr_sid->value);
            se_tree_insert_string(xmpp_info->ibb_sessions, se_id, (void*) se_sid, EMEM_TREE_STRING_NOCASE);
        }
    }
}


static void
xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *xmpp_iq_item;
    proto_tree *xmpp_iq_tree;

    attr_t *attr_id;

    attr_info attrs_info[] = {
        {"id", hf_xmpp_iq_id, TRUE, TRUE, NULL, NULL},
        {"type", hf_xmpp_iq_type, TRUE, TRUE, NULL, NULL},
        {"from", hf_xmpp_iq_from, FALSE, TRUE, NULL, NULL},
        {"to", hf_xmpp_iq_to, FALSE, TRUE, NULL, NULL},
        {"xml:lang", hf_xmpp_iq_to, FALSE, FALSE, NULL, NULL}
    };

    element_t *query_element, *error_element, *bind_element, *services_element,
        *session_element, *vcard_element, *jingle_element, *ibb_open_element,
        *ibb_close_element, *ibb_data_element;

    conversation_t *conversation = NULL;
    xmpp_conv_info_t *xmpp_info = NULL;
    xmpp_transaction_t *reqresp_trans = NULL;

    attr_id = g_hash_table_lookup(packet->attrs, "id");

    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    xmpp_iq_item = proto_tree_add_item(tree, hf_xmpp_iq, tvb, packet->offset, packet->length, TRUE);
    xmpp_iq_tree = proto_item_add_subtree(xmpp_iq_item,ett_xmpp_iq);

    display_attrs(xmpp_iq_tree, xmpp_iq_item, packet, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));


    if (check_col(pinfo->cinfo, COL_INFO))
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ");

    if((query_element = steal_element_by_name(packet,"query")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ QUERY");
        }
        xmpp_iq_query(xmpp_iq_tree,tvb,pinfo,query_element);
    }

    if((bind_element = steal_element_by_name(packet,"bind")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ BIND");
        }
        xmpp_iq_bind(xmpp_iq_tree, tvb, pinfo, bind_element);
    }

    if((services_element = steal_element_by_name(packet,"services")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ SERVICES");
        }
        xmpp_iq_services(xmpp_iq_tree,tvb,services_element);
    }

    if((session_element = steal_element_by_name(packet,"session")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ SESSION");
        }
        xmpp_iq_session(xmpp_iq_tree,tvb,session_element);
    }

    if((vcard_element = steal_element_by_name(packet,"vCard")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ VCARD");
        }
        xmpp_iq_vcard(xmpp_iq_tree,tvb,vcard_element);
    }

    if((jingle_element = steal_element_by_name(packet,"jingle")) != NULL)
    {
       

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ JINGLE");
        }
        xmpp_iq_jingle(xmpp_iq_tree,tvb,pinfo, jingle_element);
    }

    if((ibb_open_element = steal_element_by_name_and_attr(packet, "open", "xmlns", "http://jabber.org/protocol/ibb")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ IBB OPEN");
        }
        xmpp_ibb_open(xmpp_iq_tree,tvb,pinfo, ibb_open_element);
    }

    if((ibb_close_element = steal_element_by_name_and_attr(packet, "close", "xmlns", "http://jabber.org/protocol/ibb")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ IBB CLOSE");
        }
        xmpp_ibb_close(xmpp_iq_tree,tvb,pinfo, ibb_close_element);
    }

    if((ibb_data_element = steal_element_by_name_and_attr(packet, "data", "xmlns", "http://jabber.org/protocol/ibb")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ IBB DATA");
        }
        xmpp_ibb_data(xmpp_iq_tree,tvb,pinfo, ibb_data_element);
    }

    if((error_element = steal_element_by_name(packet, "error")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ ERROR");
        }
        xmpp_iq_error(xmpp_iq_tree, tvb, pinfo, error_element);
    }

    xmpp_unknown(xmpp_iq_tree, tvb, pinfo, packet);

    /*displays generated info such as req/resp tracking, jingle sid
     * in each packet related to specified jingle session and IBB sid in packet related to it*/
    if(xmpp_info && attr_id)
    {
        gchar *jingle_sid, *ibb_sid;
        
        jingle_sid = se_tree_lookup_string(xmpp_info->jingle_sessions, attr_id->value, EMEM_TREE_STRING_NOCASE);

        if (jingle_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_jingle_session, tvb, 0, 0, jingle_sid);
            PROTO_ITEM_SET_GENERATED(it);
        }

        ibb_sid = se_tree_lookup_string(xmpp_info->ibb_sessions, attr_id->value, EMEM_TREE_STRING_NOCASE);

        if (ibb_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_ibb, tvb, 0, 0, ibb_sid);
            PROTO_ITEM_SET_GENERATED(it);
        }

        reqresp_trans = se_tree_lookup_string(xmpp_info->req_resp, attr_id->value, EMEM_TREE_STRING_NOCASE);
        /*displays request/response field in each iq packet*/
        if (reqresp_trans) {

            if (reqresp_trans->req_frame == pinfo->fd->num) {
                if (reqresp_trans->resp_frame) {
                    proto_item *it = proto_tree_add_uint(tree, hf_xmpp_response_in, tvb, 0, 0, reqresp_trans->resp_frame);
                    PROTO_ITEM_SET_GENERATED(it);
                }

            } else {
                if (reqresp_trans->req_frame) {
                    proto_item *it = proto_tree_add_uint(tree, hf_xmpp_response_to, tvb, 0, 0, reqresp_trans->req_frame);
                    PROTO_ITEM_SET_GENERATED(it);
                }
            }
        }
    }

    
}

static void
xmpp_iq_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"node", hf_xmpp_iq_query_node, FALSE, TRUE, NULL, NULL}
    };

    element_t *item_element, *identity_element, *feature_element;

    query_item = proto_tree_add_item(tree, hf_xmpp_iq_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_iq_query);

    display_attrs(query_tree, query_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    while((item_element = steal_element_by_name(element, "item")) != NULL)
    {
        xmpp_iq_query_item(query_tree, tvb, pinfo, item_element);
    }

    while((identity_element = steal_element_by_name(element, "identity")) != NULL)
    {
        xmpp_iq_query_identity(query_tree, tvb, pinfo, identity_element);
    }

    while((feature_element = steal_element_by_name(element, "feature")) != NULL)
    {
        xmpp_iq_query_feature(query_tree, tvb, feature_element);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_iq_query_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    const gchar *ask_enums[] = {"subscribe"};
    const gchar *subscription_enums[] = {"both","from","none","remove","to"};

    array_t *ask_enums_array = ep_init_array_t(ask_enums,GCHARS_LEN(ask_enums));
    array_t *subscription_array = ep_init_array_t(subscription_enums,GCHARS_LEN(subscription_enums));

    attr_info attrs_info[] = {
        {"jid", hf_xmpp_iq_query_item_jid, TRUE, TRUE, NULL, NULL},
        {"name", hf_xmpp_iq_query_item_name, FALSE, TRUE, NULL, NULL},
        {"node", hf_xmpp_iq_query_item_node, FALSE, TRUE, NULL, NULL},
        {"ask", hf_xmpp_iq_query_item_ask, FALSE, TRUE, val_enum_list, ask_enums_array},
        {"approved", hf_xmpp_iq_query_item_approved, FALSE, TRUE, NULL, NULL},
        {"subscription", hf_xmpp_iq_query_item_subscription, FALSE, TRUE, val_enum_list, subscription_array},
        {"group", hf_xmpp_iq_query_item_group, FALSE, TRUE, NULL, NULL}
    };

   
    element_t *group;
    attr_t *fake_attr_group;

    group = steal_element_by_name(element,"group");
    if(group)
    {
        fake_attr_group = ep_alloc(sizeof(attr_t));
        fake_attr_group->value = group->data->value;
        fake_attr_group->offset = group->offset;
        fake_attr_group->length = group->length;
        g_hash_table_insert(element->attrs,"group",fake_attr_group);
    }

    item_item = proto_tree_add_item(tree, hf_xmpp_iq_query_item, tvb, element->offset, element->length, FALSE);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_iq_query_item);

    display_attrs(item_tree, item_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));
}

static void
xmpp_iq_query_identity(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *identity_item;
    proto_tree *identity_tree;

    attr_info attrs_info[] = {
        {"category", hf_xmpp_iq_query_identity_category, TRUE, TRUE, NULL, NULL},
        {"name", hf_xmpp_iq_query_identity_name, FALSE, TRUE, NULL, NULL},
        {"type", hf_xmpp_iq_query_identity_type, TRUE, TRUE, NULL, NULL}
    };

    identity_item = proto_tree_add_item(tree, hf_xmpp_iq_query_identity, tvb, element->offset, element->length, FALSE);
    identity_tree = proto_item_add_subtree(identity_item, ett_xmpp_iq_query_identity);

    display_attrs(identity_tree, identity_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

}

static void
xmpp_iq_query_feature(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{

    attr_t *var = g_hash_table_lookup(element->attrs, "var");

    if(var)
    {
        proto_tree_add_string_format(tree, hf_xmpp_iq_query_feature, tvb, var->offset, var->length, var->value, "FEATURE [%s]", var->value);
    }
}

static void
xmpp_iq_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *error_item;
    proto_tree *error_tree;

    element_t *text_element, *cond_element;

    attr_info attrs_info[] = {
        {"type", hf_xmpp_iq_error_type, TRUE, TRUE, NULL, NULL},
        {"code", hf_xmpp_iq_error_code, FALSE, TRUE, NULL, NULL},
        {"condition", hf_xmpp_iq_error_condition, TRUE, TRUE, NULL, NULL} /*TODO: validate list to the condition element*/
    };

    gchar *error_info;

    attr_t *fake_condition = NULL;

    error_info = ep_strdup("Stanza error");

    error_item = proto_tree_add_item(tree, hf_xmpp_iq_error, tvb, element->offset, element->length, FALSE);
    error_tree = proto_item_add_subtree(error_item, ett_xmpp_iq_query_item);

    cond_element = steal_element_by_attr(element, "xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    if(cond_element)
    {
        fake_condition = ep_init_attr_t(cond_element->name, cond_element->offset, cond_element->length);
        g_hash_table_insert(element->attrs,"condition", fake_condition);
        
        error_info = ep_strdup_printf("%s: %s;", error_info, cond_element->name);
    }


    display_attrs(error_tree, error_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    while((text_element = steal_element_by_name(element, "text")) != NULL)
    {
        xmpp_iq_error_text(error_tree, tvb, text_element);

        error_info = ep_strdup_printf("%s Text: %s", error_info, text_element->data->value);
    }

    expert_add_info_format(pinfo, error_item, PI_RESPONSE_CODE, PI_CHAT,"%s", error_info);

    xmpp_unknown(error_tree, tvb, pinfo, element);
}

static void
xmpp_iq_error_text(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    proto_tree_add_string(tree, hf_xmpp_iq_error_text, tvb, element->offset, element->length, element->data->value);
}

static void
xmpp_iq_bind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *bind_item;
    proto_tree *bind_tree;

    element_t *resource, *jid;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"resource", hf_xmpp_iq_bind_resource, FALSE, TRUE, NULL, NULL},
        {"jid", hf_xmpp_iq_bind_jid, FALSE, TRUE, NULL, NULL}
    };

    bind_item = proto_tree_add_item(tree, hf_xmpp_iq_bind, tvb, element->offset, element->length, FALSE);
    bind_tree = proto_item_add_subtree(bind_item, ett_xmpp_iq_bind);

    resource = steal_element_by_name(element, "resource");
    jid = steal_element_by_name(element, "jid");

    if(resource)
    {
        attr_t *fake_attr_res = ep_alloc(sizeof(attr_t));
        fake_attr_res->value = resource->data->value;
        fake_attr_res->offset = resource->offset;
        fake_attr_res->length = resource->length;
        g_hash_table_insert(element->attrs, "resource", fake_attr_res);
    }

    if(jid)
    {
        attr_t *fake_attr_jid = ep_alloc(sizeof(attr_t));
        fake_attr_jid->value = jid->data->value;
        fake_attr_jid->offset = jid->offset;
        fake_attr_jid->length = jid->length;
        g_hash_table_insert(element->attrs, "jid", fake_attr_jid);
    }
    
    display_attrs(bind_tree, bind_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));
    
    xmpp_unknown(bind_tree, tvb, pinfo, element);
}


static void
xmpp_iq_services(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    proto_item *services_item;

    attr_t *xmlns = g_hash_table_lookup(element->attrs, "xmlns");

    services_item = proto_tree_add_string_format(tree, hf_xmpp_iq_services, tvb, element->offset, element->length, xmlns?xmlns->value:"", "SERVICES (%s)", xmlns?xmlns->value:"");
}

static void
xmpp_iq_session(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    attr_t *xmlns  = g_hash_table_lookup(element->attrs, "xmlns");
    proto_tree_add_string_format(tree, hf_xmpp_iq_session, tvb, element->offset, element->length, xmlns?xmlns->value:"","SESSION (%s)",xmlns?xmlns->value:"");
}

static void
xmpp_iq_vcard(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    proto_item *vcard_item;
    proto_tree *vcard_tree;

    attr_t *xmlns = g_hash_table_lookup(element->attrs, "xmlns");

    element_t *content;

    vcard_item = proto_tree_add_item(tree, hf_xmpp_iq_vcard, tvb, element->offset, element->length, FALSE);\
    vcard_tree = proto_item_add_subtree(vcard_item, ett_xmpp_iq_vcard);
    
    proto_item_append_text(vcard_item, " (%s)",xmlns?xmlns->value:"");

    content = get_first_element(element);

    if(content)
    {
        proto_tree_add_string(vcard_tree, hf_xmpp_iq_vcard_content, tvb, content->offset, content->length, element_to_string(tvb, content));
    }
}

static void
xmpp_iq_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *jingle_item;
    proto_tree *jingle_tree;

    const gchar *rtp_info_msgs[] = {"active", "hold", "mute", "ringing", "unhold", "unmute"};

    const gchar *action_enums[] = {"content-accept","content-add", "content-modify",
        "content-modify", "content-remove", "description-info", "security-info",
        "session-accept", "session-info", "session-initiate", "session-terminate",
        "transport-accept", "transport-info", "transport-reject", "transport-replace"
    };

    array_t *action_array = ep_init_array_t(action_enums,sizeof(action_enums)/sizeof(gchar*));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"action", hf_xmpp_iq_jingle_action, TRUE, TRUE, val_enum_list, action_array},
        {"sid", hf_xmpp_iq_jingle_sid, TRUE, FALSE, NULL, NULL},
        {"initiator", hf_xmpp_iq_jingle_initiator, FALSE, FALSE, NULL, NULL},
        {"responder", hf_xmpp_iq_jingle_responder, FALSE, FALSE, NULL, NULL}
    };

    element_t *content; /*0-inf*/
    element_t *reason; /*0-1*/
    element_t *rtp_info;
    
    jingle_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle, tvb, element->offset, element->length, FALSE);
    jingle_tree = proto_item_add_subtree(jingle_item, ett_xmpp_iq_jingle);

    display_attrs(jingle_tree, jingle_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    while((content=steal_element_by_name(element, "content"))!=NULL)
    {
        xmpp_iq_jingle_content(jingle_tree, tvb, pinfo, content);
    }

    while((reason=steal_element_by_name(element, "reason"))!=NULL)
    {
        xmpp_iq_jingle_reason(jingle_tree, tvb, pinfo, reason);
    }

    if((rtp_info = steal_element_by_names(element, rtp_info_msgs, GCHARS_LEN(rtp_info_msgs)))!=NULL)
    {
        xmpp_iq_jingle_rtp_info(jingle_tree, tvb, pinfo, rtp_info);
    }

    xmpp_unknown(jingle_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *content_item;
    proto_tree *content_tree;

    const gchar *creator_enums[] = {"initiator","responder"};
    array_t *creator_enums_array = ep_init_array_t(creator_enums,GCHARS_LEN(creator_enums));

    attr_info attrs_info[] = {
        {"creator", hf_xmpp_iq_jingle_content_creator, TRUE, FALSE, val_enum_list, creator_enums_array},
        {"name", hf_xmpp_iq_jingle_content_name, TRUE, TRUE, NULL, NULL},
        {"disposition", hf_xmpp_iq_jingle_content_disposition, FALSE, FALSE, NULL, NULL},
        {"sensers", hf_xmpp_iq_jingle_content_senders, FALSE, FALSE, NULL, NULL}
    };

    element_t *description, *transport;

    content_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_content, tvb, element->offset, element->length, FALSE);
    content_tree = proto_item_add_subtree(content_item, ett_xmpp_iq_jingle_content);

    display_attrs(content_tree, content_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    while((description = steal_element_by_name(element, "description"))!=NULL)
        xmpp_iq_jingle_content_description(content_tree, tvb, pinfo, description);

    while((transport = steal_element_by_name(element, "transport"))!=NULL)
        xmpp_iq_jingle_cont_trans(content_tree, tvb, pinfo, transport);

    xmpp_unknown(content_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_content_description(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"media", hf_xmpp_iq_jingle_content_description_media, TRUE, TRUE, NULL, NULL},
        {"ssrc", hf_xmpp_iq_jingle_content_description_ssrc , FALSE, TRUE, NULL, NULL}
    };

    element_t *payload, *encryption, *rtp_hdr, *bandwidth, *zrtp_hash /*IMHO it shouldn't appear in description*/;

    desc_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_content_description, tvb, element->offset, element->length, FALSE);
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_iq_jingle_content_description);

    display_attrs(desc_tree, desc_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));
    
    while((payload = steal_element_by_name(element, "payload-type"))!=NULL)
        xmpp_iq_jingle_cont_desc_payload(desc_tree, tvb, pinfo, payload);

    if((bandwidth= steal_element_by_name(element, "bandwidth"))!=NULL)
        xmpp_iq_jingle_cont_desc_bandwidth(desc_tree, tvb, pinfo, bandwidth);

    if((encryption = steal_element_by_name(element, "encryption"))!=NULL)
        xmpp_iq_jingle_cont_desc_enc(desc_tree, tvb, pinfo, encryption);

    while((rtp_hdr = steal_element_by_name(element, "rtp-hdrext"))!=NULL)
        xmpp_iq_jingle_cont_desc_rtp_hdrext(desc_tree, tvb, pinfo, rtp_hdr);

    while((zrtp_hash = steal_element_by_name(element,"zrtp-hash"))!=NULL)
        xmpp_iq_jingle_cont_desc_enc_zrtp_hash(desc_tree, tvb, pinfo, zrtp_hash);


    xmpp_unknown(desc_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *payload_item;
    proto_tree *payload_tree;

    attr_info attrs_info[] = {
        {"id", hf_xmpp_iq_jingle_cont_desc_payload_id, TRUE, TRUE, NULL, NULL},
        {"channels", hf_xmpp_iq_jingle_cont_desc_payload_channels, FALSE, FALSE, NULL, NULL},
        {"clockrate", hf_xmpp_iq_jingle_cont_desc_payload_clockrate, FALSE, FALSE, NULL, NULL},
        {"maxptime", hf_xmpp_iq_jingle_cont_desc_payload_maxptime, FALSE, FALSE, NULL, NULL},
        {"name", hf_xmpp_iq_jingle_cont_desc_payload_name, FALSE, TRUE, NULL, NULL},
        {"ptime", hf_xmpp_iq_jingle_cont_desc_payload_ptime, FALSE, FALSE, NULL, NULL}
    };

    element_t *param;

    payload_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_payload, tvb, element->offset, element->length, FALSE);
    payload_tree = proto_item_add_subtree(payload_item, ett_xmpp_iq_jingle_cont_desc_payload);

    display_attrs(payload_tree, payload_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    while((param = steal_element_by_name(element,"parameter"))!=NULL)
    {
        xmpp_iq_jingle_cont_desc_payload_param(payload_tree, tvb, pinfo, param);
    }

    xmpp_unknown(payload_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_payload_param(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *param_item;
    proto_tree *param_tree;
    
    proto_item *parent_item;
    attr_t *name, *value;

    attr_info attrs_info[] = {
        {"name", hf_xmpp_iq_jingle_cont_desc_payload_param_name, TRUE, TRUE, NULL, NULL},
        {"value", hf_xmpp_iq_jingle_cont_desc_payload_param_value, TRUE, TRUE, NULL, NULL}
    };


    name = g_hash_table_lookup(element->attrs, "name");
    value = g_hash_table_lookup(element->attrs, "value");

    if(name && value)
    {
        gchar *parent_item_label;
        //gchar *new_parent_item_label;

        parent_item = proto_tree_get_parent(tree);

        parent_item_label = proto_item_get_text(parent_item);

        if(parent_item_label)
        {
            parent_item_label[strlen(parent_item_label)-1]= '\0';
            proto_item_set_text(parent_item, "%s param(\"%s\")=%s]", parent_item_label ,name->value, value->value);
        }
    }

    param_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_payload_param, tvb, element->offset, element->length, FALSE);
    param_tree = proto_item_add_subtree(param_item, ett_xmpp_iq_jingle_cont_desc_payload_param);

    display_attrs(param_tree, param_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

}

static void
xmpp_iq_jingle_cont_desc_enc(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *enc_item;
    proto_tree *enc_tree;

    element_t *zrtp_hash, *crypto;

    enc_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_enc, tvb, element->offset, element->length, FALSE);
    enc_tree = proto_item_add_subtree(enc_item, ett_xmpp_iq_jingle_cont_desc_enc);

    while((zrtp_hash = steal_element_by_name(element,"zrtp-hash"))!=NULL)
    {
        xmpp_iq_jingle_cont_desc_enc_zrtp_hash(enc_tree, tvb, pinfo, zrtp_hash);
    }

    while((crypto = steal_element_by_name(element,"crypto"))!=NULL)
    {
        xmpp_iq_jingle_cont_desc_enc_crypto(enc_tree, tvb, pinfo, crypto);
    }

    xmpp_unknown(enc_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_enc_zrtp_hash(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *zrtp_hash_item;
    proto_tree *zrtp_hash_tree;

     attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"version", -1, TRUE, TRUE,NULL,NULL},
        {"hash", -1, TRUE, FALSE, NULL, NULL}
    };

    zrtp_hash_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_enc_zrtp_hash, tvb, element->offset, element->length, FALSE);
    zrtp_hash_tree = proto_item_add_subtree(zrtp_hash_item, ett_xmpp_iq_jingle_cont_desc_enc_zrtp_hash);

    if(element->data)
    {
        attr_t *fake_hash = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "hash", fake_hash);
    }

    display_attrs(zrtp_hash_tree, zrtp_hash_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(zrtp_hash_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_enc_crypto(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *crypto_item;
    proto_tree *crypto_tree;

     attr_info attrs_info[] = {
        {"crypto-suite", -1, TRUE, TRUE, NULL, NULL},
        {"key-params", -1, TRUE, FALSE,NULL,NULL},
        {"session-params", -1, FALSE, TRUE, NULL, NULL},
        {"tag", -1, TRUE, FALSE, NULL, NULL}
    };

    crypto_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_enc_crypto, tvb, element->offset, element->length, FALSE);
    crypto_tree = proto_item_add_subtree(crypto_item, ett_xmpp_iq_jingle_cont_desc_enc_crypto);


    display_attrs(crypto_tree, crypto_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(crypto_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_bandwidth(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *bandwidth_item;
    proto_tree *bandwidth_tree;

    attr_info attrs_info[] = {
        {"type", -1, TRUE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    bandwidth_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_bandwidth, tvb, element->offset, element->length, FALSE);
    bandwidth_tree = proto_item_add_subtree(bandwidth_item, ett_xmpp_iq_jingle_cont_desc_bandwidth);

    if(element->data)
    {
        attr_t *fake_value = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_value);
    }

    display_attrs(bandwidth_tree, bandwidth_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));
}

/*TODO description(zrtp-hash - sometimes zrtp-hash
 *  appears in encryption element, but when it comes from server, it is in descrytion...)*/

static void
xmpp_iq_jingle_cont_desc_rtp_hdrext(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *rtp_hdr_item;
    proto_tree *rtp_hdr_tree;

    const gchar *senders[] = {"both", "initiator", "responder"};
    array_t *senders_enums = ep_init_array_t(senders, 3);

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"id", -1, TRUE, FALSE, NULL, NULL},
        {"uri", -1, TRUE, TRUE, NULL, NULL},
        {"senders", -1, FALSE, TRUE, val_enum_list, senders_enums}
    };

    rtp_hdr_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_rtp_hdr, tvb, element->offset, element->length, FALSE);
    rtp_hdr_tree = proto_item_add_subtree(rtp_hdr_item, ett_xmpp_iq_jingle_cont_desc_rtp_hdr);

    display_attrs(rtp_hdr_tree, rtp_hdr_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

}

static void
xmpp_iq_jingle_cont_trans(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"pwd", hf_xmpp_iq_jingle_cont_trans_pwd, FALSE, FALSE, NULL, NULL},
        {"ufrag", hf_xmpp_iq_jingle_cont_trans_ufrag, FALSE, TRUE, NULL, NULL}
    };

    element_t *candidate, *remote_candidate;

    trans_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_trans, tvb, element->offset, element->length, FALSE);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_iq_jingle_cont_trans);

    display_attrs(trans_tree, trans_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    while((candidate = steal_element_by_name(element, "candidate"))!=NULL)
    {
        xmpp_iq_jingle_cont_trans_candidate(trans_tree, tvb, pinfo, candidate);
    }

    while((remote_candidate = steal_element_by_name(element, "remote-candidate"))!=NULL)
    {
        xmpp_iq_jingle_cont_trans_remote_candidate(trans_tree, tvb, pinfo, remote_candidate);
    }

    xmpp_unknown(trans_tree, tvb, pinfo, element);
    
}

static void
xmpp_iq_jingle_cont_trans_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    const gchar *type_enums[] = {"host", "prflx", "relay", "srflx"};
    array_t *type_enums_array = ep_init_array_t(type_enums,GCHARS_LEN(type_enums));

    attr_info attrs_info[] = {
        {"component", -1, TRUE, FALSE, NULL, NULL},
        {"foundation", -1, TRUE, FALSE, NULL, NULL},
        {"generation", -1, TRUE, FALSE, NULL, NULL},
        {"id", -1, FALSE, FALSE, NULL, NULL}, /*in schemas id is marked as required, but in jitsi logs it doesn't appear*/
        {"ip", -1, TRUE, FALSE, NULL, NULL},
        {"network", -1, TRUE, FALSE, NULL, NULL},
        {"port", -1, TRUE, FALSE, NULL, NULL},
        {"priority", -1, TRUE, FALSE, NULL, NULL},
        {"protocol", -1, TRUE, TRUE, NULL, NULL},
        {"rel-addr", -1, FALSE, FALSE, NULL, NULL},
        {"rel-port", -1, FALSE, FALSE, NULL, NULL},
        {"type", -1, TRUE, TRUE, val_enum_list, type_enums_array}
    };

    cand_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_trans_cand, tvb, element->offset, element->length, FALSE);
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_iq_jingle_cont_trans_cand);

    display_attrs(cand_tree, cand_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(cand_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_trans_remote_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *remote_cand_item;
    proto_tree *remote_cand_tree;

    attr_info attrs_info[] = {
        {"component", -1, TRUE, FALSE, NULL, NULL},
        {"ip", -1, TRUE, FALSE, NULL, NULL},
        {"port", -1, TRUE, FALSE, NULL, NULL}
    };

    remote_cand_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_trans_rem_cand, tvb, element->offset, element->length, FALSE);
    remote_cand_tree = proto_item_add_subtree(remote_cand_item, ett_xmpp_iq_jingle_cont_trans_rem_cand);

    display_attrs(remote_cand_tree, remote_cand_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(remote_cand_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *reason_item;
    proto_tree *reason_tree;

    attr_info attrs_info[] = {
        {"condition", hf_xmpp_iq_jingle_reason_condition, TRUE, TRUE, NULL, NULL},
        {"sid", -1, FALSE, TRUE, NULL, NULL},
        {"rtp-error", -1, FALSE, TRUE, NULL, NULL},
        {"text", hf_xmpp_iq_jingle_reason_text, FALSE, FALSE, NULL, NULL}
   };

    element_t *condition; /*1?*/
    element_t *text; /*0-1*/
    element_t *rtp_error;

    const gchar *reason_names[] = { "success", "busy", "failed-application", "cancel", "connectivity-error",
        "decline", "expired", "failed-transport", "general-error", "gone", "incompatible-parameters",
        "media-error", "security-error", "timeout", "unsupported-applications", "unsupported-transports"};

    const gchar *rtp_error_names[] = {"crypto-required", "invalid-crypto"};

    reason_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_reason, tvb, element->offset, element->length, FALSE);
    reason_tree = proto_item_add_subtree(reason_item, ett_xmpp_iq_jingle_reason);


    /*Looks for reason description. "alternative-session" may contain "sid" element
     Elements are changed into attribute*/
    if((condition = steal_element_by_names(element, reason_names, GCHARS_LEN(reason_names)))!=NULL)
    {
        attr_t *fake_cond = ep_init_attr_t(condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, "condition", fake_cond);

    } else if((condition = steal_element_by_name(element, "alternative-session"))!=NULL)
    {
        attr_t *fake_cond,*fake_alter_sid;
        element_t *sid;
        
        fake_cond = ep_init_attr_t(condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, "condition", fake_cond);


        if((sid = steal_element_by_name(element, "sid"))!=NULL)
        {
            fake_alter_sid = ep_init_attr_t(sid->name, sid->offset, sid->length);
            g_hash_table_insert(element->attrs, "sid", fake_alter_sid);
        }
    }

    if((rtp_error = steal_element_by_names(element, rtp_error_names, GCHARS_LEN(rtp_error_names)))!=NULL)
    {
        attr_t *fake_rtp_error = ep_init_attr_t(rtp_error->name, rtp_error->offset, rtp_error->length);
        g_hash_table_insert(element->attrs, "rtp-error", fake_rtp_error);
    }

    if((text = steal_element_by_name(element, "text"))!=NULL)
    {
        attr_t *fake_text = ep_init_attr_t(text->data?text->data->value:"", text->offset, text->length);
        g_hash_table_insert(element->attrs, "text", fake_text);
    }

    display_attrs(reason_tree, reason_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(reason_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_rtp_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *rtp_info_item;
    proto_tree *rtp_info_tree;

    const gchar *creator[] = {"initiator","responder"};
    array_t *creator_enums = ep_init_array_t(creator, GCHARS_LEN(creator));

    attr_info mute_attrs_info[] = {
        {"creator", -1, TRUE, TRUE, val_enum_list, creator_enums},
        {"name", -1, TRUE, TRUE, NULL, NULL}
    };

    rtp_info_item = proto_tree_add_string(tree, hf_xmpp_iq_jingle_rtp_info, tvb, element->offset, element->length, element->name);
    rtp_info_tree = proto_item_add_subtree(rtp_info_item, ett_xmpp_iq_jingle_rtp_info);

    if(strcmp("mute", element->name) == 0 || strcmp("unmute", element->name) == 0)
        display_attrs(rtp_info_tree, rtp_info_item, element, pinfo, tvb, mute_attrs_info, AINFO_LEN(mute_attrs_info));
}

static void
xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *presence_item;
    proto_tree *presence_tree;

    const gchar *type_enums[] = {"error", "probe", "subscribe", "subscribed",
        "unavailable", "unsubscribe", "unsubscribed"};
    array_t *type_array = ep_init_array_t(type_enums, GCHARS_LEN(type_enums));

    const gchar *show_enums[] = {"away", "chat", "dnd", "xa"};
    array_t *show_array = ep_init_array_t(show_enums, GCHARS_LEN(show_enums));

    attr_info attrs_info[] = {
        {"from", -1, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_presence_id, FALSE, TRUE, NULL, NULL},
        {"to", -1, FALSE, FALSE, NULL, NULL},
        {"type", hf_xmpp_presence_type, FALSE, TRUE, val_enum_list, type_array},
        {"xml:lang",-1, FALSE, FALSE, NULL,NULL},
        {"show", hf_xmpp_presence_show, FALSE, TRUE, val_enum_list, show_array},
        {"priority", -1, FALSE, FALSE, NULL, NULL}
    };

    element_t *show, *priority, *status, *caps;

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "PRESENCE");

    presence_item = proto_tree_add_item(tree, hf_xmpp_presence, tvb, packet->offset, packet->length, FALSE);
    presence_tree = proto_item_add_subtree(presence_item, ett_xmpp_presence);

    if((show = steal_element_by_name(packet, "show"))!=NULL)
    {
        attr_t *fake_show = ep_init_attr_t(show->data?show->data->value:"",show->offset, show->length);
        g_hash_table_insert(packet->attrs, "show", fake_show);
    }

    if((priority = steal_element_by_name(packet, "priority"))!=NULL)
    {
        attr_t *fake_priority = ep_init_attr_t(priority->data?priority->data->value:"",priority->offset, priority->length);
        g_hash_table_insert(packet->attrs, "priority", fake_priority);
    }
    display_attrs(presence_tree, presence_item, packet, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    while((status = steal_element_by_name(packet, "status"))!=NULL)
    {
        xmpp_presence_status(presence_tree, tvb, pinfo, status);
    }

    if((caps = steal_element_by_name_and_attr(packet, "c", "xmlns", "http://jabber.org/protocol/caps"))!=NULL)
    {
        xmpp_presence_caps(presence_tree, tvb, pinfo, caps);
    }
   

    xmpp_unknown(presence_tree, tvb, pinfo, packet);
}

static void
xmpp_presence_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *status_item;
    proto_tree *status_tree;

    attr_info attrs_info[] = {
        {"xml:lang", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    attr_t *fake_value;

    status_item = proto_tree_add_item(tree, hf_xmpp_presence_status, tvb, element->offset, element->length, FALSE);
    status_tree = proto_item_add_subtree(status_item, ett_xmpp_presence_status);

    if(element->data)
        fake_value = ep_init_attr_t(element->data->value, element->offset, element->length);
    else
        fake_value = ep_init_attr_t("(empty)", element->offset, element->length);


    g_hash_table_insert(element->attrs, "value", fake_value);
    
    display_attrs(status_tree, status_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(status_tree, tvb, pinfo, element);
}

static void
xmpp_presence_caps(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *caps_item;
    proto_tree *caps_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"ext", -1, FALSE, FALSE, NULL, NULL},
        {"hash", -1, TRUE, TRUE, NULL, NULL},
        {"node", -1, TRUE, TRUE, NULL, NULL},
        {"ver", -1, TRUE, FALSE, NULL, NULL}
    };

    caps_item = proto_tree_add_item(tree, hf_xmpp_presence_caps, tvb, element->offset, element->length, FALSE);
    caps_tree = proto_item_add_subtree(caps_item, ett_xmpp_presence_caps);

    display_attrs(caps_tree, caps_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(caps_tree, tvb, pinfo, element);
}

static void
xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *message_item;
    proto_tree *message_tree;

    const gchar *type_enums[] = {"chat", "error", "groupchat", "headline", "normal"};
    array_t *type_array = ep_init_array_t(type_enums, GCHARS_LEN(type_enums));

    attr_info attrs_info[] = {
        {"from", -1, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_message_id, FALSE, TRUE, NULL, NULL},
        {"to", -1, FALSE, FALSE, NULL, NULL},
        {"type", hf_xmpp_message_type, FALSE, TRUE, val_enum_list, type_array},
        {"xml:lang",-1, FALSE, FALSE, NULL,NULL},
        {"chatstate", hf_xmpp_message_chatstate, FALSE, TRUE, NULL, NULL}
    };

    element_t *ibb_data_element, *thread, *chatstate, *body, *subject;

    attr_t *id = NULL;

    conversation_t *conversation = NULL;
    xmpp_conv_info_t *xmpp_info = NULL;

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "MESSAGE");

    id = g_hash_table_lookup(packet->attrs, "id");

    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    message_item = proto_tree_add_item(tree, hf_xmpp_message, tvb, packet->offset, packet->length, FALSE);
    message_tree = proto_item_add_subtree(message_item, ett_xmpp_message);

    if((chatstate = steal_element_by_attr(packet, "xmlns", "http://jabber.org/protocol/chatstates"))!=NULL)
    {
        attr_t *fake_chatstate_attr = ep_init_attr_t(chatstate->name, chatstate->offset, chatstate->length);
        g_hash_table_insert(packet->attrs, "chatstate", fake_chatstate_attr);
    }

    display_attrs(message_tree, message_item, packet, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    if((ibb_data_element = steal_element_by_name_and_attr(packet, "data", "xmlns", "http://jabber.org/protocol/ibb")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "MESSAGE IBB DATA");
        }
        xmpp_ibb_data(message_tree,tvb,pinfo, ibb_data_element);
    }


    if((thread = steal_element_by_name(packet, "thread"))!=NULL)
    {
        xmpp_message_thread(message_tree, tvb, pinfo, thread);
    }
    while((body = steal_element_by_name(packet, "body"))!=NULL)
    {
        xmpp_message_body(message_tree, tvb, pinfo, body);
    }
    while((subject = steal_element_by_name(packet, "subject"))!=NULL)
    {
        xmpp_message_subject(message_tree, tvb, pinfo, subject);
    }



    xmpp_unknown(message_tree, tvb, pinfo, packet);

    /*Displays data about IBB session*/
    if(xmpp_info && id)
    {
        gchar *ibb_sid;

        ibb_sid = se_tree_lookup_string(xmpp_info->ibb_sessions, id->value, EMEM_TREE_STRING_NOCASE);

        if (ibb_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_ibb, tvb, 0, 0, ibb_sid);
            PROTO_ITEM_SET_GENERATED(it);
        }
        
    }
}

static void
xmpp_message_body(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *body_item;
    proto_tree *body_tree;

    attr_info attrs_info[] = {
        {"xml:lang", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    body_item = proto_tree_add_item(tree, hf_xmpp_message_body, tvb, element->offset, element->length, FALSE);
    body_tree = proto_item_add_subtree(body_item, ett_xmpp_message_body);

    if(element->data)
    {
        attr_t *fake_data_attr = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_data_attr);
    }

    display_attrs(body_tree, body_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(body_tree, tvb, pinfo, element);
}

static void xmpp_message_subject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element) {
    proto_item *subject_item;
    proto_tree *subject_tree;

    attr_info attrs_info[] = {
        {"xml:lang", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, FALSE, NULL, NULL}
    };

    subject_item = proto_tree_add_item(tree, hf_xmpp_message_subject, tvb, element->offset, element->length, FALSE);
    subject_tree = proto_item_add_subtree(subject_item, ett_xmpp_message_subject);

    if (element->data) {
        attr_t *fake_data_attr = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_data_attr);
    }

    display_attrs(subject_tree, subject_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(subject_tree, tvb, pinfo, element);
}

static void
xmpp_message_thread(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *thread_item;
    proto_tree *thread_tree;

    attr_info attrs_info[] = {
        {"parent", hf_xmpp_message_thread_parent, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    thread_item = proto_tree_add_item(tree, hf_xmpp_message_thread, tvb, element->offset, element->length, FALSE);
    thread_tree = proto_item_add_subtree(thread_item, ett_xmpp_message_thread);

    if(element->data)
    {
        attr_t *fake_value = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_value);
    }

    display_attrs(thread_tree, thread_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    xmpp_unknown(thread_tree, tvb, pinfo, element);
}

static void
xmpp_ibb_open(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *open_item;
    proto_tree *open_tree;

    const gchar *stanza_enums[] = {"iq","message"};
    array_t *stanza_array = ep_init_array_t(stanza_enums, GCHARS_LEN(stanza_enums));
    
    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"sid", -1, TRUE, TRUE, NULL, NULL},
        {"block-size", -1, TRUE, TRUE, NULL, NULL},
        {"stanza", -1, FALSE, TRUE, val_enum_list, stanza_array}
    };

    open_item = proto_tree_add_item(tree, hf_xmpp_ibb_open, tvb, element->offset, element->length, FALSE);
    open_tree = proto_item_add_subtree(open_item, ett_xmpp_ibb_open);

    display_attrs(open_tree, open_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));
    xmpp_unknown(open_tree, tvb, pinfo, element);
}

static void
xmpp_ibb_close(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *close_item;
    proto_tree *close_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"sid", -1, TRUE, TRUE, NULL, NULL}
    };

    close_item = proto_tree_add_item(tree, hf_xmpp_ibb_close, tvb, element->offset, element->length, FALSE);
    close_tree = proto_item_add_subtree(close_item, ett_xmpp_ibb_close);

    display_attrs(close_tree, close_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));
    xmpp_unknown(close_tree, tvb, pinfo, element);
}

static void
xmpp_ibb_data(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *data_item;
    proto_tree *data_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"sid", -1, TRUE, TRUE, NULL, NULL},
        {"seq", -1, TRUE, TRUE, NULL, NULL},
        {"value", -1, FALSE, FALSE, NULL, NULL}
    };

    data_item = proto_tree_add_item(tree, hf_xmpp_ibb_data, tvb, element->offset, element->length, FALSE);
    data_tree = proto_item_add_subtree(data_item, ett_xmpp_ibb_data);

    if(element->data)
    {
        attr_t *fake_data = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_data);
    }
    
    display_attrs(data_tree, data_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));
    xmpp_unknown(data_tree, tvb, pinfo, element);
}

static void
xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *auth_item;
    proto_tree *auth_tree;

    attr_t *xmlns, *mechanism;

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "AUTH");

    auth_item = proto_tree_add_item(tree, hf_xmpp_auth, tvb, packet->offset, packet->length, FALSE);
    auth_tree = proto_item_add_subtree(auth_item, ett_xmpp_auth);

    xmlns = g_hash_table_lookup(packet->attrs,"xmlns");
    mechanism = g_hash_table_lookup(packet->attrs, "mechanism");

    proto_item_append_text(auth_item," [");

    if(xmlns)
    {
        proto_item_append_text(auth_item,"xmlns=%s ",xmlns->value);
    }

    if(mechanism)
    {
        proto_item_append_text(auth_item,"mechanism=%s",mechanism->value);
        proto_tree_add_string(auth_tree,hf_xmpp_auth_mechanism, tvb, mechanism->offset, mechanism->length, mechanism->value);
    }
    proto_item_append_text(auth_item,"]");

    if(packet->data)
        proto_tree_add_string(auth_tree, hf_xmpp_auth_content, tvb, packet->data->offset, packet->data->length, packet->data->value);

    xmpp_unknown(auth_tree, tvb, pinfo, packet);
}

static void
xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, element_t *packet, gint hf, gint ett,
    gint hf_content, const char *col_info)
{
    proto_item *item;
    proto_tree *subtree;

    attr_t *xmlns;

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, col_info);

    item = proto_tree_add_item(tree, hf, tvb, packet->offset, packet->length, FALSE);
    subtree = proto_item_add_subtree(item, ett);

    xmlns = g_hash_table_lookup(packet->attrs,"xmlns");

    if(xmlns)
    {
        proto_item_append_text(item," [xmlns=%s]",xmlns->value);
    }

    if(packet->data)
    {
        proto_tree_add_string(subtree, hf_content, tvb, packet->data->offset, packet->data->length, packet->data->value);
    }
    xmpp_unknown(subtree, tvb, pinfo, packet);
}

/*TODO xmpp_failure - when auth failure*/

static void
xmpp_unknown(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    guint i;

    //element has unrecognized elements
    for(i = 0; i<g_list_length(element->elements); i++)
    {
        element_t *child = g_list_nth_data(element->elements,i);
        proto_item *unknown_item= proto_tree_add_string(tree, hf_xmpp_unknown, tvb, child->offset, child->length, element_to_string(tvb, child));
        expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_NOTE,"Unknown element: %s", child->name);
    }
}


static void
dissect_xmpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    
    xml_frame_t *xml_frame;
    gboolean is_request;

    conversation_t *conversation;
    xmpp_conv_info_t *xmpp_info;

    proto_tree *xmpp_tree = NULL;
    proto_item *xmpp_item = NULL;

    element_t *packet;

    if(check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "XMPP");

    if (check_col(pinfo->cinfo, COL_INFO))
            col_clear(pinfo->cinfo, COL_INFO);

    //if tree == NULL then xmpp_item and xmpp_tree will also NULL
    xmpp_item = proto_tree_add_item(tree,proto_xmpp, tvb, 0, -1, FALSE);
    xmpp_tree = proto_item_add_subtree(xmpp_item, ett_xmpp);
    

    call_dissector(xml_handle,tvb,pinfo,xmpp_tree);
    //data from XML dissector
    xml_frame = ((xml_frame_t*)pinfo->private_data)->first_child;
    packet = xml_frame_to_element_t(xml_frame);

    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    if (!xmpp_info) {
        xmpp_info = se_alloc(sizeof (xmpp_conv_info_t));
        xmpp_info->req_resp = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_req_resp");
        xmpp_info->jingle_sessions = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_jingle_sessions");
         xmpp_info->ibb_sessions = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_ibb_sessions");
        conversation_add_proto_data(conversation, proto_xmpp, (void *) xmpp_info);
    }

    
    if (pinfo->match_uint == pinfo->destport)
        is_request = TRUE;
    else
        is_request = FALSE;

    if (strcmp(packet->name,"iq") == 0)
    {
        xmpp_iq_reqresp_track(pinfo, packet, xmpp_info);
        xmpp_jingle_session_track(pinfo, packet, xmpp_info);
    }

    if (strcmp(packet->name,"iq") == 0 || strcmp(packet->name,"message") == 0)
    {
        xmpp_ibb_session_track(pinfo, packet, xmpp_info);
    }

    if (tree) { /* we are being asked for details */
        proto_item *reqresp_item;

        if(is_request)
            reqresp_item = proto_tree_add_boolean(xmpp_tree, hf_xmpp_req, tvb, 0, 0, TRUE);
        else
            reqresp_item = proto_tree_add_boolean(xmpp_tree, hf_xmpp_res, tvb, 0, 0, TRUE);
        
        PROTO_ITEM_SET_HIDDEN(reqresp_item);
        

        //it hides tree generated by XML dissector
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
            xmpp_challenge_response_success(xmpp_tree, tvb, pinfo, packet, hf_xmpp_challenge, ett_xmpp_challenge, hf_xmpp_challenge_content, "CHALLENGE");
        } else  if(strcmp(packet->name,"response") == 0)
        {
            xmpp_challenge_response_success(xmpp_tree, tvb, pinfo, packet, hf_xmpp_response, ett_xmpp_response, hf_xmpp_response_content, "RESPONSE");
        } else  if(strcmp(packet->name,"success") == 0)
        {
            xmpp_challenge_response_success(xmpp_tree, tvb, pinfo, packet, hf_xmpp_success, ett_xmpp_success, hf_xmpp_success_content, "SUCCESS");
        } else
        {
            proto_tree_show_first_child(xmpp_tree);
            expert_add_info_format(pinfo, xmpp_tree, PI_UNDECODED, PI_NOTE, "Unknown packet: %s", packet->name );
        }
        
    }
}


void
proto_register_xmpp(void) {
    static hf_register_info hf[] = {
        { &hf_xmpp_iq,
            {
                "IQ", "xmpp.iq", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq", HFILL
            }},
            {&hf_xmpp_xmlns,
            {
                "xmlns", "xmpp.xmlns", FT_STRING, BASE_NONE, NULL, 0x0,
                "xmlns", HFILL
            }},
            { &hf_xmpp_iq_id,
            {
                "id", "xmpp.iq.id", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq id", HFILL
            }},
            { &hf_xmpp_iq_type,
            {
                "type", "xmpp.iq.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq type", HFILL
            }},
             { &hf_xmpp_iq_from,
            {
                "from", "xmpp.iq.from", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq from", HFILL
            }},
             { &hf_xmpp_iq_to,
            {
                "to", "xmpp.iq.to", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq to", HFILL
            }},
            { &hf_xmpp_iq_query,
            {
                "QUERY", "xmpp.iq.query", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query", HFILL
            }},
            { &hf_xmpp_iq_query_xmlns,
            {
                "xmlns", "xmpp.iq.query.xmlns", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query xmlns", HFILL
            }},
            { &hf_xmpp_iq_query_node,
            {
                "node", "xmpp.iq.query.node", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query node", HFILL
            }},
            { &hf_xmpp_iq_query_item,
            {
                "ITEM", "xmpp.iq.query.item", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query item", HFILL

            }},
            { &hf_xmpp_iq_query_item_jid,
            {
                "jid", "xmpp.iq.query.item.jid", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item jid", HFILL

            }},
            { &hf_xmpp_iq_query_item_name,
            {
                "name", "xmpp.iq.query.item.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item name", HFILL
            }},
            { &hf_xmpp_iq_query_item_subscription,
            {
                "subscription", "xmpp.iq.query.item.subscription", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item subscription", HFILL
            }},
            { &hf_xmpp_iq_query_item_ask,
            {
                "ask", "xmpp.iq.query.item.ask", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item ask", HFILL
            }},
            { &hf_xmpp_iq_query_item_group,
            {
                "GROUP", "xmpp.iq.query.item.group", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item group", HFILL

            }},
            { &hf_xmpp_iq_query_item_approved,
            {
                "approved", "xmpp.iq.query.item.approved", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item approved", HFILL

            }},
            { &hf_xmpp_iq_query_item_node,
            {
                "node", "xmpp.iq.query.item.node", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query item node", HFILL

            }},
            { &hf_xmpp_iq_query_identity,
            {
                "IDENTITY", "xmpp.iq.query.identity", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq query identity", HFILL

            }},
            { &hf_xmpp_iq_query_identity_category,
            {
                "category", "xmpp.iq.query.identity.category", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query identity category", HFILL

            }},
            { &hf_xmpp_iq_query_identity_type,
            {
                "type", "xmpp.iq.query.identity.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query identity type", HFILL

            }},
            { &hf_xmpp_iq_query_identity_name,
            {
                "name", "xmpp.iq.query.identity.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query identity name", HFILL

            }},
            { &hf_xmpp_iq_query_identity_lang,
            {
                "lang", "xmpp.iq.query.identity.lang", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query identity lang", HFILL

            }},
            { &hf_xmpp_iq_query_feature,
            {
                "FEATURE", "xmpp.iq.query.feature", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq query feature", HFILL

            }},
            { &hf_xmpp_iq_error,
            {
                "ERROR", "xmpp.iq.error", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq error", HFILL
            }},
            { &hf_xmpp_iq_error_code,
            {
                "code", "xmpp.iq.error.code", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza error code", HFILL

            }},
            { &hf_xmpp_iq_error_type,
            {
                "type", "xmpp.iq.error.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq error type", HFILL

            }},
            { &hf_xmpp_iq_error_condition,
            {
                "CONDITION", "xmpp.iq.error.condition", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq error condition", HFILL

            }},
            { &hf_xmpp_iq_error_text,
            {
                "TEXT", "xmpp.iq.error.text", FT_STRING, BASE_NONE, NULL, 0x0,
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
            { &hf_xmpp_iq_vcard,
            {
                "VCARD", "xmpp.iq.vcard", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq vCard", HFILL
            }},
            { &hf_xmpp_iq_vcard_content,
            {
                "CONTENT", "xmpp.iq.vcard.content", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq vCard content", HFILL
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
            { &hf_xmpp_iq_jingle_content_description_xmlns,
            {
                "xmlns", "xmpp.iq.jingle.content.description.xmlns", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq jingle content description xmlns", HFILL
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
            { &hf_xmpp_presence,
            {
                "PRESENCE", "xmpp.presence", FT_NONE, BASE_NONE, NULL, 0x0,
                "presence", HFILL
            }},
            { &hf_xmpp_presence_id,
            {
                "id", "xmpp.presence.id", FT_STRING, BASE_NONE, NULL, 0x0,
                "presence id", HFILL
            }},
            { &hf_xmpp_presence_type,
            {
                "type", "xmpp.presence.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "presence type", HFILL
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
                "message", HFILL
            }},
            { &hf_xmpp_message_id,
            {
                "id", "xmpp.message.id", FT_STRING, BASE_NONE, NULL, 0x0,
                "message id", HFILL
            }},
            { &hf_xmpp_message_type,
            {
                "type", "xmpp.message.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "message type", HFILL
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
                "auth", HFILL
            }},
            { &hf_xmpp_auth_mechanism,
            {
                "mechanism", "xmpp.auth.mechanism", FT_STRING, BASE_NONE, NULL, 0x0,
                "auth mechanism", HFILL
            }},
            { &hf_xmpp_auth_content,
            {
                "CONTENT", "xmpp.auth.content", FT_STRING, BASE_NONE, NULL, 0x0,
                "auth content", HFILL
            }},
            { &hf_xmpp_challenge,
            {
                "CHALLENGE", "xmpp.challenge", FT_NONE, BASE_NONE, NULL, 0x0,
                "challenge", HFILL
            }},
            { &hf_xmpp_challenge_content,
            {
                "CONTENT", "xmpp.challenge.content", FT_STRING, BASE_NONE, NULL, 0x0,
                "challenge content", HFILL
            }},
            { &hf_xmpp_response,
            {
                "RESPONSE", "xmpp.response", FT_NONE, BASE_NONE, NULL, 0x0,
                "response", HFILL
            }},
            { &hf_xmpp_response_content,
            {
                "CONTENT", "xmpp.response.content", FT_STRING, BASE_NONE, NULL, 0x0,
                "response content", HFILL
            }},
            { &hf_xmpp_success,
            {
                "SUCCESS", "xmpp.success", FT_NONE, BASE_NONE, NULL, 0x0,
                "success", HFILL
            }},
            { &hf_xmpp_success_content,
            {
                "CONTENT", "xmpp.success.content", FT_STRING, BASE_NONE, NULL, 0x0,
                "success content", HFILL
            }},
            { &hf_xmpp_unknown,
            {
                "UNKNOWN", "xmpp.unknown", FT_STRING, BASE_NONE, NULL, 0x0,
                "unknown", HFILL
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
            { &hf_xmpp_req,
            {
                "Request", "xmpp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "XMPP_REQ", HFILL
            }},
            { &hf_xmpp_res,
            {
                "Response", "xmpp.res", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "XMPP_RES", HFILL
            }},
            { &hf_xmpp_ibb,
            {
                "IBB SESSION", "xmpp.ibb", FT_STRING, BASE_NONE, NULL, 0x0,
                "In-Band Bytestreams session", HFILL
            }},
            { &hf_xmpp_jingle_session,
            {
                "JINGLE SESSION", "xmpp.jingle_session", FT_STRING, BASE_NONE, NULL, 0x0,
                "Jingle session", HFILL
            }}
    };

    static gint * ett[] = {
        &ett_xmpp,
        &ett_xmpp_iq,
        &ett_xmpp_iq_query,
        &ett_xmpp_iq_query_item,
        &ett_xmpp_iq_query_identity,
        &ett_xmpp_iq_query_feature,
        &ett_xmpp_iq_error,
        &ett_xmpp_iq_bind,
        &ett_xmpp_iq_vcard,
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
        &ett_xmpp_ibb_open,
        &ett_xmpp_ibb_close,
        &ett_xmpp_ibb_data,
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
    };

    proto_xmpp = proto_register_protocol(
            "XMPP Protocol", /* name       */
            "XMPP", /* short name */
            "xmpp" /* abbrev     */
            );
    proto_register_field_array(proto_xmpp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_xmpp(void) {
    static dissector_handle_t xmpp_handle;

    xml_handle = find_dissector("xml");

    xmpp_handle = create_dissector_handle(dissect_xmpp, proto_xmpp);

    dissector_add("tcp.port", XMPP_PORT, xmpp_handle);
}
