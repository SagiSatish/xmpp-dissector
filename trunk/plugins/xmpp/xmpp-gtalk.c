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

#include <plugins/xmpp/packet-xmpp.h>
#include <plugins/xmpp/xmpp.h>
#include <plugins/xmpp/xmpp-gtalk.h>


static void xmpp_gtalk_session_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_gtalk_session_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_gtalk_session_cand(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_gtalk_session_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_gtalk_jingleinfo_stun(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_gtalk_jingleinfo_server(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_gtalk_jingleinfo_relay(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_gtalk_jingleinfo_relay_serv(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_gtalk_nosave_item(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

void
xmpp_gtalk_session(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *session_item;
    proto_tree *session_tree;

    attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"type", hf_xmpp_gtalk_session_type, TRUE, TRUE, NULL, NULL},
        {"initiator", -1, FALSE, TRUE, NULL, NULL},
        {"id", -1, TRUE, TRUE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME,"description", xmpp_gtalk_session_desc, ONE},
        {NAME, "candidate", xmpp_gtalk_session_cand, MANY},
        {NAME, "reason", xmpp_gtalk_session_reason, ONE}
    };

    attr_t *attr_type = g_hash_table_lookup(element->attrs, "type");

    col_append_fstr(pinfo->cinfo, COL_INFO, "GTALK-SESSION(%s) ", attr_type?attr_type->value:"");

    session_item = proto_tree_add_item(tree, hf_xmpp_gtalk_session, tvb, element->offset, element->length, FALSE);
    session_tree = proto_item_add_subtree(session_item, ett_xmpp_gtalk_session);

    display_attrs(session_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(session_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_session_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    elem_info elems_info[] = {
        {NAME, "payload-type", xmpp_gtalk_session_desc_payload, MANY}
    };

    desc_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "DESCRIPTION");
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_gtalk_session_desc);

    display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(desc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_session_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *payload_item;
    proto_tree *payload_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL},
        {"id", -1, FALSE, TRUE, NULL, NULL},
        {"name", -1, FALSE, TRUE, NULL, NULL},
        {"channels", -1, FALSE, FALSE, NULL, NULL},
        {"clockrate", -1, FALSE, FALSE, NULL, NULL},
        {"bitrate", -1, FALSE, FALSE, NULL, NULL},
        {"width", -1, FALSE, FALSE, NULL, NULL},
        {"height", -1, FALSE, FALSE, NULL, NULL},
        {"framerate", -1, FALSE, FALSE, NULL, NULL},
    };

    payload_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "PAYLOAD-TYPE");
    payload_tree = proto_item_add_subtree(payload_item, ett_xmpp_gtalk_session_desc_payload);

    display_attrs(payload_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(payload_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_session_cand(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    attr_info attrs_info[] = {
        {"name", -1, TRUE, TRUE, NULL, NULL},
        {"address", -1, TRUE, FALSE, NULL, NULL},
        {"port", -1, TRUE, FALSE, NULL, NULL},
        {"preference", -1, TRUE, FALSE, NULL, NULL},
        {"type", -1, TRUE, TRUE, NULL, NULL},
        {"protocol", -1, TRUE, TRUE, NULL, NULL},
        {"network", -1, TRUE, FALSE, NULL, NULL},
        {"username", -1, TRUE, FALSE, NULL, NULL},
        {"password", -1, TRUE, FALSE, NULL, NULL},
        {"generation", -1, TRUE, FALSE, NULL, NULL},
        {"foundation", -1, FALSE, FALSE, NULL, NULL},
        {"component", -1, FALSE, FALSE, NULL, NULL}
    };

    cand_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "CANDIDATE");
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_gtalk_session_cand);

    display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(cand_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_session_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *reason_item;
    proto_tree *reason_tree;

    attr_info attrs_info[] = {
        {"condition", -1, TRUE, TRUE, NULL, NULL},
        {"text", -1, FALSE, FALSE, NULL, NULL}
   };

    element_t *condition;
    element_t *text;
  
    const gchar *reason_names[] = { "success", "busy"};

    reason_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "REASON");
    reason_tree = proto_item_add_subtree(reason_item, ett_xmpp_gtalk_session_reason);


    /*Looks for reason description.*/
    if((condition = steal_element_by_names(element, reason_names, array_length(reason_names)))!=NULL)
    {
        attr_t *fake_cond = ep_init_attr_t(condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, "condition", fake_cond);

    } 

    if((text = steal_element_by_name(element, "text"))!=NULL)
    {
        attr_t *fake_text = ep_init_attr_t(text->data?text->data->value:"", text->offset, text->length);
        g_hash_table_insert(element->attrs, "text", fake_text);
    }

    display_attrs(reason_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(reason_tree, tvb, pinfo, element);
}

void
xmpp_gtalk_jingleinfo_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME, "stun", xmpp_gtalk_jingleinfo_stun, ONE},
        {NAME, "relay", xmpp_gtalk_jingleinfo_relay, ONE}
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(google:jingleinfo) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_jingleinfo_stun(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *stun_item;
    proto_tree *stun_tree;

    elem_info elems_info [] = {
        {NAME, "server", xmpp_gtalk_jingleinfo_server, MANY},
    };

    stun_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "STUN");
    stun_tree = proto_item_add_subtree(stun_item, ett_xmpp_gtalk_jingleinfo_stun);

    display_attrs(stun_tree, element, pinfo, tvb, NULL, 0);
    display_elems(stun_tree, element, pinfo, tvb, elems_info, array_length(elems_info));

}

static void
xmpp_gtalk_jingleinfo_server(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *serv_item;
    proto_tree *serv_tree;

    attr_info attrs_info[] = {
        {"host", -1, TRUE, TRUE, NULL, NULL},
        {"udp", -1, TRUE, TRUE, NULL, NULL}
    };

    serv_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "SERVER");
    serv_tree = proto_item_add_subtree(serv_item, ett_xmpp_gtalk_jingleinfo_server);

    display_attrs(serv_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(serv_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_gtalk_jingleinfo_relay(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *relay_item;
    proto_tree *relay_tree;

    attr_info attrs_info[] = {
        {"token", -1, FALSE, FALSE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME, "server", xmpp_gtalk_jingleinfo_relay_serv, ONE}
    };

    element_t *token;

    relay_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "RELAY");
    relay_tree = proto_item_add_subtree(relay_item, ett_xmpp_gtalk_jingleinfo_relay);

    if((token  = steal_element_by_name(element, "token"))!=NULL)
    {
        attr_t *fake_token = ep_init_attr_t(token->data?token->data->value:"", token->offset, token->length);
        g_hash_table_insert(element->attrs, "token", fake_token);
    }

    display_attrs(relay_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(relay_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_jingleinfo_relay_serv(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *serv_item;
    proto_tree *serv_tree;

    attr_info attrs_info[] = {
        {"host", -1, TRUE, TRUE, NULL, NULL},
        {"udp", -1, FALSE, TRUE, NULL, NULL},
        {"tcp", -1, FALSE, TRUE, NULL, NULL},
        {"tcpssl", -1, FALSE, TRUE, NULL, NULL}
    };

    serv_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "SERVER");
    serv_tree = proto_item_add_subtree(serv_item, ett_xmpp_gtalk_jingleinfo_relay_serv);

    display_attrs(serv_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(serv_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_gtalk_usersetting(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *sett_item;
    proto_tree *sett_tree;

    attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    guint i;

    sett_item = proto_tree_add_item(tree, hf_xmpp_gtalk_setting, tvb, element->offset, element->length, FALSE);
    sett_tree = proto_item_add_subtree(sett_item, ett_xmpp_gtalk_setting);

    display_attrs(sett_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    for(i = 0; i < g_list_length(element->elements); i++)
    {
        GList *elem_l = g_list_nth(element->elements,i);
        element_t *elem = elem_l?elem_l->data:NULL;

        if(elem)
        {
            attr_t *val = g_hash_table_lookup(elem->attrs,"value");
            proto_tree_add_text(sett_tree, tvb, elem->offset, elem->length, "%s [%s]",elem->name,val?val->value:"");
        }
    }
    g_list_free(element->elements);
}

void
xmpp_gtalk_nosave_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element) {
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME, "item", xmpp_gtalk_nosave_item, MANY},
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(google:nosave) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_nosave_item(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL,NULL},
        {"jid", -1, TRUE, TRUE, NULL, NULL},
        {"source", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    item_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "ITEM");
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_query_item);

    display_attrs(item_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(item_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_gtalk_nosave_x(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"value", -1, FALSE, TRUE, NULL, NULL}
    };

    x_item = proto_tree_add_item(tree, hf_xmpp_gtalk_nosave_x, tvb, element->offset, element->length, FALSE);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_gtalk_nosave_x);


    display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(x_tree, element, pinfo, tvb, NULL, 0);
}