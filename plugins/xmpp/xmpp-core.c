/* jabber:client
 * urn:ietf:params:xml:ns:xmpp-sasl
 */

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
#include <plugins/xmpp/xmpp-gtalk.h>

#include <epan/strutil.h>


void xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
void xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, element_t *packet, gint hf, gint ett, const char *col_info);

void xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);

static void xmpp_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_error_text(proto_tree *tree, tvbuff_t *tvb, element_t *element);

void xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_presence_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_message_thread(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_message_body(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_message_subject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void xmpp_failure(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_failure_text(proto_tree *tree, tvbuff_t *tvb, element_t *element);

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

    conversation_t *conversation = NULL;
    xmpp_conv_info_t *xmpp_info = NULL;
    xmpp_transaction_t *reqresp_trans = NULL;

    elem_info elems_info [] = {
        {NAME_AND_ATTR, name_attr_struct("query", "xmlns","http://jabber.org/protocol/disco#items"), xmpp_disco_items_query, ONE},
        {NAME_AND_ATTR, name_attr_struct("query", "xmlns", "jabber:iq:roster"), xmpp_roster_query, ONE},
        {NAME_AND_ATTR, name_attr_struct("query", "xmlns", "http://jabber.org/protocol/disco#info"), xmpp_disco_info_query, ONE},
        {NAME_AND_ATTR, name_attr_struct("query", "xmlns", "http://jabber.org/protocol/bytestreams"), xmpp_bytestreams_query, ONE},
        {NAME_AND_ATTR, name_attr_struct("query", "xmlns", "http://jabber.org/protocol/muc#owner"), xmpp_muc_owner_query, ONE},
        {NAME_AND_ATTR, name_attr_struct("query", "xmlns", "http://jabber.org/protocol/muc#admin"), xmpp_muc_admin_query, ONE},
        {NAME, "bind", xmpp_iq_bind, ONE},
        {NAME, "services", xmpp_iq_services, ONE},
        {NAME_AND_ATTR, name_attr_struct("session", "xmlns", "urn:ietf:params:xml:ns:xmpp-session"), xmpp_session, ONE},
        {NAME, "vCard", xmpp_vcard, ONE},
        {NAME, "jingle", xmpp_iq_jingle, ONE},
        {NAME_AND_ATTR, name_attr_struct("open", "xmlns", "http://jabber.org/protocol/ibb"), xmpp_ibb_open, ONE},
        {NAME_AND_ATTR, name_attr_struct("close", "xmlns", "http://jabber.org/protocol/ibb"), xmpp_ibb_close, ONE},
        {NAME_AND_ATTR, name_attr_struct("data", "xmlns", "http://jabber.org/protocol/ibb"), xmpp_ibb_data, ONE},
        {NAME, "si", xmpp_si, ONE},
        {NAME, "error", xmpp_error, ONE},
        {NAME_AND_ATTR, name_attr_struct("session", "xmlns", "http://www.google.com/session"), xmpp_gtalk_session, ONE}
    };

    attr_id = g_hash_table_lookup(packet->attrs, "id");
    attr_type = g_hash_table_lookup(packet->attrs, "type");

    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    xmpp_iq_item = proto_tree_add_item(tree, hf_xmpp_iq, tvb, packet->offset, packet->length, TRUE);
    xmpp_iq_tree = proto_item_add_subtree(xmpp_iq_item,ett_xmpp_iq);

    display_attrs(xmpp_iq_tree, packet, pinfo, tvb, attrs_info,  array_length(attrs_info));


    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "IQ(%s) ", attr_type?attr_type->value:"");

    display_elems(xmpp_iq_tree, pinfo, tvb, packet, elems_info, array_length(elems_info));

    /*appends to COL_INFO information about src or dst*/
    if (pinfo->match_uint == pinfo->destport)
    {
        attr_t *to = g_hash_table_lookup(packet->attrs, "to");
        if(to)
            col_append_fstr(pinfo->cinfo, COL_INFO, "> %s ",to->value);
    } else
    {
        attr_t *from = g_hash_table_lookup(packet->attrs, "from");
        if(from)
            col_append_fstr(pinfo->cinfo, COL_INFO, "< %s ",from->value);
    }

    /*displays generated info such as req/resp tracking, jingle sid
     * in each packet related to specified jingle session and IBB sid in packet related to it*/
    if(xmpp_info && attr_id)
    {
        gchar *jingle_sid, *ibb_sid, *gtalk_sid;

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

        gtalk_sid = se_tree_lookup_string(xmpp_info->gtalk_sessions, attr_id->value, EMEM_TREE_STRING_NOCASE);

        if (gtalk_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_gtalk, tvb, 0, 0, gtalk_sid);
            PROTO_ITEM_SET_GENERATED(it);
        }

        reqresp_trans = se_tree_lookup_string(xmpp_info->req_resp, attr_id->value, EMEM_TREE_STRING_NOCASE);
        /*displays request/response field in each iq packet*/
        if (reqresp_trans) {

            if (reqresp_trans->req_frame == pinfo->fd->num) {
                if (reqresp_trans->resp_frame) {
                    proto_item *it = proto_tree_add_uint(tree, hf_xmpp_response_in, tvb, 0, 0, reqresp_trans->resp_frame);
                    PROTO_ITEM_SET_GENERATED(it);
                } else
                {
                    expert_add_info_format(pinfo, xmpp_iq_item , PI_PROTOCOL, PI_CHAT, "Packet without response");
                }

            } else {
                if (reqresp_trans->req_frame) {
                    proto_item *it = proto_tree_add_uint(tree, hf_xmpp_response_to, tvb, 0, 0, reqresp_trans->req_frame);
                    PROTO_ITEM_SET_GENERATED(it);
                } else
                {
                    expert_add_info_format(pinfo, xmpp_iq_item , PI_PROTOCOL, PI_CHAT, "Packet without response");
                }
            }
        }
    }


}


static void
xmpp_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *error_item;
    proto_tree *error_tree;

    element_t *text_element, *cond_element;

    attr_info attrs_info[] = {
        {"type", hf_xmpp_error_type, TRUE, TRUE, NULL, NULL},
        {"code", hf_xmpp_error_code, FALSE, TRUE, NULL, NULL},
        {"condition", hf_xmpp_error_condition, TRUE, TRUE, NULL, NULL} /*TODO: validate list to the condition element*/
    };

    gchar *error_info;

    attr_t *fake_condition = NULL;

    error_info = ep_strdup("Stanza error");

    error_item = proto_tree_add_item(tree, hf_xmpp_error, tvb, element->offset, element->length, FALSE);
    error_tree = proto_item_add_subtree(error_item, ett_xmpp_iq_query_item);

    cond_element = steal_element_by_attr(element, "xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    if(cond_element)
    {
        fake_condition = ep_init_attr_t(cond_element->name, cond_element->offset, cond_element->length);
        g_hash_table_insert(element->attrs,"condition", fake_condition);

        error_info = ep_strdup_printf("%s: %s;", error_info, cond_element->name);
    }


    display_attrs(error_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((text_element = steal_element_by_name(element, "text")) != NULL)
    {
        xmpp_error_text(error_tree, tvb, text_element);

        error_info = ep_strdup_printf("%s Text: %s", error_info, text_element->data?text_element->data->value:"");
    }
 
    expert_add_info_format(pinfo, error_item, PI_RESPONSE_CODE, PI_CHAT,"%s", error_info);

    xmpp_unknown(error_tree, tvb, pinfo, element);
}

static void
xmpp_error_text(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    proto_tree_add_string(tree, hf_xmpp_error_text, tvb, element->offset, element->length, element->data?element->data->value:"");
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

    elem_info elems_info[] = {
        {NAME, "status", xmpp_presence_status, MANY},
        {NAME_AND_ATTR, name_attr_struct("c","xmlns","http://jabber.org/protocol/caps"), xmpp_presence_caps, ONE},
        {NAME, "delay", xmpp_delay, ONE},
        {NAME_AND_ATTR, name_attr_struct("x","xmlns", "vcard-temp:x:update"), xmpp_vcard_x_update, ONE},
        {NAME_AND_ATTR, name_attr_struct("x","xmlns","http://jabber.org/protocol/muc"), xmpp_muc_x, ONE},
        {NAME_AND_ATTR, name_attr_struct("x","xmlns","http://jabber.org/protocol/muc#user"), xmpp_muc_user_x, ONE},
        {NAME, "error", xmpp_error, ONE}
    };


    element_t *show, *priority;

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
    display_attrs(presence_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(presence_tree, pinfo, tvb, packet, elems_info, array_length(elems_info));
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

    display_attrs(status_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    elem_info elems_info [] = {
        {NAME_AND_ATTR, name_attr_struct("data", "xmlns", "http://jabber.org/protocol/ibb"), xmpp_ibb_data, ONE},
        {NAME, "thread", xmpp_message_thread, ONE},
        {NAME, "body", xmpp_message_body, MANY},
        {NAME, "subject", xmpp_message_subject, MANY},
        {NAME, "delay", xmpp_delay, ONE},
        {NAME_AND_ATTR, name_attr_struct("x","xmlns","jabber:x:event"), xmpp_x_event, ONE},
        {NAME_AND_ATTR, name_attr_struct("x","xmlns","http://jabber.org/protocol/muc#user"), xmpp_muc_user_x, ONE}
    };

    element_t *chatstate;

    attr_t *id = NULL;

    conversation_t *conversation = NULL;
    xmpp_conv_info_t *xmpp_info = NULL;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "MESSAGE ");

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

    display_attrs(message_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(message_tree, pinfo, tvb, packet, elems_info, array_length(elems_info));
  
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


    display_attrs(body_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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


    display_attrs(subject_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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


    display_attrs(thread_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(thread_tree, tvb, pinfo, element);
}

void
xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *auth_item;
    proto_tree *auth_tree;

    attr_info attrs_info[]={
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"mechanism", -1, TRUE, TRUE, NULL, NULL},
        {"value", -1, TRUE, FALSE,NULL,NULL}
    };

    attr_t *fake_cdata;

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "AUTH");

    auth_item = proto_tree_add_item(tree, hf_xmpp_auth, tvb, packet->offset, packet->length, FALSE);
    auth_tree = proto_item_add_subtree(auth_item, ett_xmpp_auth);

    fake_cdata = ep_init_attr_t(packet->data?packet->data->value:"", packet->offset, packet->length);
    g_hash_table_insert(packet->attrs,"value",fake_cdata);

    display_attrs(auth_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(auth_tree, tvb, pinfo, packet);
}

void
xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, element_t *packet, gint hf, gint ett,  const char *col_info)
{
    proto_item *item;
    proto_tree *subtree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"value", -1, FALSE, TRUE, NULL, NULL}
    };

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, col_info);

    item = proto_tree_add_item(tree, hf, tvb, packet->offset, packet->length, FALSE);
    subtree = proto_item_add_subtree(item, ett);

    if(packet->data)
    {
        attr_t *fake_cdata = ep_init_attr_t(packet->data->value, packet->data->offset, packet->data->length);
        g_hash_table_insert(packet->attrs, "value", fake_cdata);
    }
    
    display_attrs(subtree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));
   
    xmpp_unknown(subtree, tvb, pinfo, packet);
}

void
xmpp_failure(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *fail_item;
    proto_tree *fail_tree;

    
    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"condition", -1, FALSE, TRUE, NULL, NULL}
    };

    const gchar *fail_names[] = {"aborted","account-disabled", "credentials-expired",
        "encryption-required", "incorrect-encoding", "invalid-authzid", "invalid-mechanism",
        "malformed-request", "mechanism-too-weak", "not-authorized", "temporary-auth-failure",
        "transition-needed"
    };

    element_t *fail_condition, *text;

    col_add_fstr(pinfo->cinfo, COL_INFO, "FAILURE");

    fail_item = proto_tree_add_item(tree, hf_xmpp_failure, tvb, packet->offset, packet->length, FALSE);
    fail_tree = proto_item_add_subtree(fail_item, ett_xmpp_failure);

    if((fail_condition = steal_element_by_names(packet, fail_names, array_length(fail_names)))!=NULL)
    {
        attr_t *fake_cond = ep_init_attr_t(fail_condition->name, fail_condition->offset, fail_condition->length);
        g_hash_table_insert(packet->attrs, "condition", fake_cond);
    }

    if((text = steal_element_by_name(packet, "text"))!=NULL)
    {
        xmpp_failure_text(fail_tree, tvb, text);
    }

    display_attrs(fail_tree, packet, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(fail_tree, tvb, pinfo, packet);
}

static void
xmpp_failure_text(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    attr_t *lang = g_hash_table_lookup(element->attrs,"xml:lang");
    
    proto_tree_add_text(tree, tvb, element->offset, element->length, "TEXT%s: %s",
            lang?ep_strdup_printf("(%s)",lang->value):"",
            element->data?element->data->value:"");
}