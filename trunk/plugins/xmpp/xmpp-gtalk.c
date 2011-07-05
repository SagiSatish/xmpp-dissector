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

    col_append_fstr(pinfo->cinfo, COL_INFO, "GTALK(%s) ", attr_type?attr_type->value:"");

    session_item = proto_tree_add_item(tree, hf_xmpp_gtalk_session, tvb, element->offset, element->length, FALSE);
    session_tree = proto_item_add_subtree(session_item, ett_xmpp_gtalk_session);

    display_attrs(session_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(session_tree, pinfo, tvb, element, elems_info, array_length(elems_info));
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
    display_elems(desc_tree, pinfo, tvb, element, elems_info, array_length(elems_info));
}

static void
xmpp_gtalk_session_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *payload_item;
    proto_tree *payload_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"id", -1, FALSE, TRUE, NULL, NULL},
        {"name", -1, FALSE, TRUE, NULL, NULL},
        {"channels", -1, FALSE, FALSE, NULL, NULL},
        {"clockrate", -1, FALSE, FALSE, NULL, NULL},
        {"bitrate", -1, FALSE, FALSE, NULL, NULL},
        {"width", -1, FALSE, FALSE, NULL, NULL},
        {"height", -1, FALSE, FALSE, NULL, NULL},
        {"framerate", -1, FALSE, FALSE, NULL, NULL},
    };

    elem_info elems_info[] = {

    };

    payload_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "PAYLOAD-TYPE");
    payload_tree = proto_item_add_subtree(payload_item, ett_xmpp_gtalk_session_desc_payload);

    display_attrs(payload_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(payload_tree, pinfo, tvb, element, elems_info, array_length(elems_info));
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

    elem_info elems_info[] = {

    };

    cand_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "CANDIDATE");
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_gtalk_session_cand);

    display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(cand_tree, pinfo, tvb, element, elems_info, array_length(elems_info));
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