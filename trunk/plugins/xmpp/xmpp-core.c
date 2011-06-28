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

#include <epan/dissectors/packet-xml.h>

#include <plugins/xmpp/xmpp.h>
#include <plugins/xmpp/packet-xmpp.h>
#include <plugins/xmpp/xmpp-core.h>
#include <plugins/xmpp/xmpp-jingle.h>
#include <plugins/xmpp/xmpp-other.h>

#include <epan/strutil.h>


void xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
void xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, element_t *packet, gint hf, gint ett,
    gint hf_content, const char *col_info);

void xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_iq_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_iq_error_text(proto_tree *tree, tvbuff_t *tvb, element_t *element);

void xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_presence_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_message_thread(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_message_body(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_message_subject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);


void
xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *xmpp_iq_item;
    proto_tree *xmpp_iq_tree;

    attr_t *attr_id, *attr_type;

    attr_info attrs_info[] = {
        {"id", hf_xmpp_id, TRUE, TRUE, NULL, NULL},
        {"type", hf_xmpp_type, TRUE, TRUE, NULL, NULL},
        {"from", hf_xmpp_from, FALSE, TRUE, NULL, NULL},
        {"to", hf_xmpp_to, FALSE, TRUE, NULL, NULL},
        {"xml:lang", -1, FALSE, FALSE, NULL, NULL}
    };

    element_t *query_element, *error_element, *bind_element, *services_element,
        *session_element, *vcard_element, *jingle_element, *ibb_open_element,
        *ibb_close_element, *ibb_data_element, *si;

    conversation_t *conversation = NULL;
    xmpp_conv_info_t *xmpp_info = NULL;
    xmpp_transaction_t *reqresp_trans = NULL;

    attr_id = g_hash_table_lookup(packet->attrs, "id");
    attr_type = g_hash_table_lookup(packet->attrs, "type");

    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    xmpp_iq_item = proto_tree_add_item(tree, hf_xmpp_iq, tvb, packet->offset, packet->length, TRUE);
    xmpp_iq_tree = proto_item_add_subtree(xmpp_iq_item,ett_xmpp_iq);

    display_attrs(xmpp_iq_tree, xmpp_iq_item, packet, pinfo, tvb, attrs_info,  array_length(attrs_info));



    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "IQ(%s) ", attr_type?attr_type->value:"");

    if((query_element = steal_element_by_name(packet,"query")) != NULL)
    {

        attr_t *xmlns = g_hash_table_lookup(query_element->attrs, "xmlns");

        col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(%s) ",xmlns?xmlns->value:"");

        xmpp_iq_query(xmpp_iq_tree,tvb,pinfo,query_element);
    }

    if((bind_element = steal_element_by_name(packet,"bind")) != NULL)
    {

        col_append_fstr(pinfo->cinfo, COL_INFO, "BIND ");

        xmpp_iq_bind(xmpp_iq_tree, tvb, pinfo, bind_element);
    }

    if((services_element = steal_element_by_name(packet,"services")) != NULL)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "SERVICES ");

        xmpp_iq_services(xmpp_iq_tree,tvb,services_element);
    }

    if((session_element = steal_element_by_name(packet,"session")) != NULL)
    {

        col_append_fstr(pinfo->cinfo, COL_INFO, "SESSION ");

        xmpp_iq_session(xmpp_iq_tree,tvb,session_element);
    }

    if((vcard_element = steal_element_by_name(packet,"vCard")) != NULL)
    {

        col_append_fstr(pinfo->cinfo, COL_INFO, "VCARD ");

        xmpp_iq_vcard(xmpp_iq_tree, tvb, pinfo, vcard_element);
    }

    if((jingle_element = steal_element_by_name(packet,"jingle")) != NULL)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "JINGLE ");

        xmpp_iq_jingle(xmpp_iq_tree,tvb,pinfo, jingle_element);
    }

    if((ibb_open_element = steal_element_by_name_and_attr(packet, "open", "xmlns", "http://jabber.org/protocol/ibb")) != NULL)
    {

        col_append_fstr(pinfo->cinfo, COL_INFO, "IBB-OPEN ");

        xmpp_ibb_open(xmpp_iq_tree,tvb,pinfo, ibb_open_element);
    }

    if((ibb_close_element = steal_element_by_name_and_attr(packet, "close", "xmlns", "http://jabber.org/protocol/ibb")) != NULL)
    {

        col_append_fstr(pinfo->cinfo, COL_INFO, "IBB-CLOSE ");

        xmpp_ibb_close(xmpp_iq_tree,tvb,pinfo, ibb_close_element);
    }

    if((ibb_data_element = steal_element_by_name_and_attr(packet, "data", "xmlns", "http://jabber.org/protocol/ibb")) != NULL)
    {

        col_append_fstr(pinfo->cinfo, COL_INFO, "IBB-DATA ");

        xmpp_ibb_data(xmpp_iq_tree,tvb,pinfo, ibb_data_element);
    }

    if((si = steal_element_by_name(packet, "si")) != NULL)
    {

        col_append_fstr(pinfo->cinfo, COL_INFO, "SI ");

        xmpp_si(xmpp_iq_tree,tvb,pinfo, si);
    }

    if((error_element = steal_element_by_name(packet, "error")) != NULL)
    {
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


    display_attrs(error_tree, error_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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


void
xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *presence_item;
    proto_tree *presence_tree;

    const gchar *type_enums[] = {"error", "probe", "subscribe", "subscribed",
        "unavailable", "unsubscribe", "unsubscribed"};
    array_t *type_array = ep_init_array_t(type_enums, array_length(type_enums));

    const gchar *show_enums[] = {"away", "chat", "dnd", "xa"};
    array_t *show_array = ep_init_array_t(show_enums, array_length(show_enums));

    attr_info attrs_info[] = {
        {"from", hf_xmpp_from, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_id, FALSE, TRUE, NULL, NULL},
        {"to", hf_xmpp_to, FALSE, FALSE, NULL, NULL},
        {"type", hf_xmpp_type, FALSE, TRUE, val_enum_list, type_array},
        {"xml:lang",-1, FALSE, FALSE, NULL,NULL},
        {"show", hf_xmpp_presence_show, FALSE, TRUE, val_enum_list, show_array},
        {"priority", -1, FALSE, FALSE, NULL, NULL}
    };

    element_t *show, *priority, *status, *caps, *delay;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "PRESENCE");

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
    display_attrs(presence_tree, presence_item, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((status = steal_element_by_name(packet, "status"))!=NULL)
    {
        xmpp_presence_status(presence_tree, tvb, pinfo, status);
    }

    if((caps = steal_element_by_name_and_attr(packet, "c", "xmlns", "http://jabber.org/protocol/caps"))!=NULL)
    {
        xmpp_presence_caps(presence_tree, tvb, pinfo, caps);
    }

    while((delay = steal_element_by_name(packet, "delay"))!=NULL)
    {
        xmpp_delay(presence_tree, tvb, pinfo, delay);
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

    display_attrs(status_tree, status_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(status_tree, tvb, pinfo, element);
}


void
xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *message_item;
    proto_tree *message_tree;

    const gchar *type_enums[] = {"chat", "error", "groupchat", "headline", "normal"};
    array_t *type_array = ep_init_array_t(type_enums, array_length(type_enums));

    attr_info attrs_info[] = {
        {"from", hf_xmpp_from, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_id, FALSE, TRUE, NULL, NULL},
        {"to", hf_xmpp_to, FALSE, FALSE, NULL, NULL},
        {"type", hf_xmpp_type, FALSE, TRUE, val_enum_list, type_array},
        {"xml:lang",-1, FALSE, FALSE, NULL,NULL},
        {"chatstate", hf_xmpp_message_chatstate, FALSE, TRUE, NULL, NULL}
    };

    element_t *ibb_data_element, *thread, *chatstate, *body, *subject, *delay;

    attr_t *id = NULL;

    conversation_t *conversation = NULL;
    xmpp_conv_info_t *xmpp_info = NULL;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "message ");

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

    display_attrs(message_tree, message_item, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    if((ibb_data_element = steal_element_by_name_and_attr(packet, "data", "xmlns", "http://jabber.org/protocol/ibb")) != NULL)
    {

        col_append_fstr(pinfo->cinfo, COL_INFO, "ibb-data ");

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

    while((delay = steal_element_by_name(packet, "delay"))!=NULL)
    {
        xmpp_delay(message_tree, tvb, pinfo, delay);
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

    attr_t *fake_data_attr;

    body_item = proto_tree_add_item(tree, hf_xmpp_message_body, tvb, element->offset, element->length, FALSE);
    body_tree = proto_item_add_subtree(body_item, ett_xmpp_message_body);

    fake_data_attr = ep_init_attr_t(element->data?element->data->value:"", element->offset, element->length);
    g_hash_table_insert(element->attrs, "value", fake_data_attr);


    display_attrs(body_tree, body_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(body_tree, tvb, pinfo, element);
}

static void
xmpp_message_subject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element) {
    proto_item *subject_item;
    proto_tree *subject_tree;

    attr_info attrs_info[] = {
        {"xml:lang", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, FALSE, NULL, NULL}
    };

    attr_t *fake_data_attr;

    subject_item = proto_tree_add_item(tree, hf_xmpp_message_subject, tvb, element->offset, element->length, FALSE);
    subject_tree = proto_item_add_subtree(subject_item, ett_xmpp_message_subject);


    fake_data_attr = ep_init_attr_t(element->data?element->data->value:"", element->offset, element->length);
    g_hash_table_insert(element->attrs, "value", fake_data_attr);


    display_attrs(subject_tree, subject_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    attr_t *fake_value;

    thread_item = proto_tree_add_item(tree, hf_xmpp_message_thread, tvb, element->offset, element->length, FALSE);
    thread_tree = proto_item_add_subtree(thread_item, ett_xmpp_message_thread);

    fake_value = ep_init_attr_t(element->data?element->data->value:"", element->offset, element->length);
    g_hash_table_insert(element->attrs, "value", fake_value);


    display_attrs(thread_tree, thread_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(thread_tree, tvb, pinfo, element);
}

void
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

void
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