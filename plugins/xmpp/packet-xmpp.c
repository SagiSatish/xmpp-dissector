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

#include <glib.h>


#define XMPP_PORT 5222

typedef struct _xml_attr_t{
    gchar *value;
    gint offset;
    gint length;
} xml_attr_t;

typedef struct _xml_data_t{
    gchar *value;

    gint offset;
    gint length;
} xml_data_t;

typedef struct _xml_node_t{
    gchar* name;
    GHashTable *attrs;
    GList *elements;
    xml_data_t *data;
    proto_item *item;

    gint offset;
    gint length;
} xml_node_t;

typedef struct _xmpp_conv_info_t {
    emem_tree_t *req_resp;
    emem_tree_t *jingle_sessions;
} xmpp_conv_info_t;

typedef struct _xmpp_reqresp_transaction_t {
    guint32 req_frame;
    guint32 resp_frame;
} xmpp_transaction_t;

static int proto_xmpp = -1;

static gint hf_xmpp_iq = -1;
static gint hf_xmpp_presence = -1;
static gint hf_xmpp_message = -1;

static gint hf_xmpp_req = -1;
static gint hf_xmpp_res = -1;
static gint hf_xmpp_response_in = -1;
static gint hf_xmpp_response_to = -1;
static gint hf_xmpp_jingle_session = -1;

static gint ett_xmpp = -1;
static gint ett_xmpp_xml = -1;

static dissector_handle_t xml_handle = NULL;


static gint
xml_node_cmp(gconstpointer a, gconstpointer b)
{
    return strcmp(((xml_node_t*)a)->name,((xml_node_t*)b)->name);
}

static GList*
find_elements_by_name(xml_node_t *packet,const gchar *name)
{
    GList *found_elements;
    xml_node_t *search_element;

    //create fake elementonly with name
    search_element = ep_alloc(sizeof(xml_node_t));
    search_element->name = ep_strdup(name);

    found_elements = g_list_find_custom(packet->elements, search_element, xml_node_cmp);
    
    if(found_elements)
        return found_elements;
    else
        return NULL;
}

static xml_node_t*
get_first_element_by_name(xml_node_t *packet, const gchar *name)
{
    GList *elements = find_elements_by_name(packet,name);
    if(elements)
        return elements->data;
    else
        return NULL;
}


//it converts xml_frame_t structure, which is from XML dissector to xml_node_t (simpler representation)
static xml_node_t*
xml_frame_to_xml_node(xml_frame_t *xml_frame)
{
    static gint start_offset = -1;
    xml_frame_t *child;
    xml_node_t *node = ep_alloc0(sizeof(xml_node_t));


    node->attrs = g_hash_table_new(g_str_hash, g_str_equal);
    node->elements = NULL;
    node->data = NULL;
    node->item = NULL;

    node->name = ep_strdup(xml_frame->name_orig_case);
    node->offset = 0;
    node->length = 0;

    if(start_offset == -1 && xml_frame->item != NULL)
        start_offset = xml_frame->item->finfo->start;


    if(xml_frame->item != NULL)
    {
        node->item = xml_frame->item;
        node->offset = xml_frame->item->finfo->start - start_offset;
        node->length = xml_frame->item->finfo->length;
    }


    child = xml_frame->first_child;

    while(child)
    {
        if(child->type != XML_FRAME_TAG)
        {
            if(child->type == XML_FRAME_ATTRIB)
            {
                gint l;
                gchar *value = NULL;

                xml_attr_t *xml_attr = ep_alloc(sizeof(xml_attr_t));
                xml_attr->length = 0;
                xml_attr->offset = 0;

                if (child->value != NULL && child->value->initialized) {
                    l = tvb_reported_length(child->value);
                    value = ep_alloc0(l + 1);
                    tvb_memcpy(child->value, value, 0, l);
                }

                if(child->item)
                {
                    xml_attr->offset = child->item->finfo->start - start_offset;
                    xml_attr->length = child->item->finfo->length;
                }
                xml_attr->value = value;

                g_hash_table_insert(node->attrs,(gpointer)child->name_orig_case,(gpointer)xml_attr);
            }
            else if( child->type == XML_FRAME_CDATA)
            {
                xml_data_t *xml_data = NULL;
                gint l;
                gchar* value = NULL;

                xml_data = ep_alloc(sizeof(xml_data_t));
                xml_data->length = 0;
                xml_data->offset = 0;

                if (child->value != NULL && child->value->initialized) {
                    l = tvb_reported_length(child->value);
                    value = ep_alloc0(l + 1);
                    tvb_memcpy(child->value, value, 0, l);
                }

                xml_data->value = value;

                if(child->item)
                {
                    xml_data->offset = child->item->finfo->start - start_offset;
                    xml_data->length = child->item->finfo->length;
                }
                node->data = xml_data;
            }
        } else
        {
            node->elements = g_list_append(node->elements,(gpointer)xml_frame_to_xml_node(child));
        }
        
        child = child->next_sibling;
    }
    return node;
}


static gchar*
node_to_string(tvbuff_t *tvb, xml_node_t *node)
{
    gchar *buff;

    if(tvb && tvb->initialized)
    {
        buff = ep_alloc0(node->length+1);
        tvb_memcpy(tvb,buff,node->offset,node->length);
        return buff;
    } else
    {
        return NULL;
    }
}

/*
static void
xml_tree_delete()
{
    //TODO
}
*/

static xmpp_transaction_t*
xmpp_iq_reqresp_track(packet_info *pinfo, xml_node_t *packet, xmpp_conv_info_t *xmpp_info)
{
    xmpp_transaction_t *xmpp_trans = NULL;

    xml_attr_t *attr_id;
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
xmpp_iq_jingle_session_track(packet_info *pinfo, xml_node_t *packet, xmpp_conv_info_t *xmpp_info)
{
    xml_node_t *jingle_packet;

    jingle_packet = get_first_element_by_name(packet,"jingle");

    if (jingle_packet && !pinfo->fd->flags.visited) {
        xml_attr_t *attr_id;
        xml_attr_t *attr_sid;

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
xmpp_iq_errors_expert_info(packet_info *pinfo, xml_node_t *packet)
{
    xml_attr_t *attr_type;

    attr_type = g_hash_table_lookup(packet->attrs, "type");
    if(attr_type && strcmp(attr_type->value,"error")==0)
    {
        xml_node_t *error = get_first_element_by_name(packet,"error");

        if(error)
        {
            gchar *buff= ep_strdup("Stanza error");
            GList *child_elem = error->elements;

            while(child_elem)
            {
                xml_node_t *node = child_elem->data;

                buff = ep_strdup_printf("%s; %s",buff,node->name);
                if(node->data)
                {
                    xml_data_t *data = node->data;
                    buff = ep_strdup_printf("%s:%s",buff,data->value);
                }

                child_elem = child_elem->next;
            }

            expert_add_info_format(pinfo, error->item, PI_RESPONSE_CODE, PI_NOTE,"%s", buff);
        }
    }
}

static void
xmpp_iq(proto_tree *tree, tvbuff_t *tvb)
{
    proto_item *item = proto_tree_add_boolean(tree, hf_xmpp_iq, tvb, 0, 0, TRUE);
    PROTO_ITEM_SET_HIDDEN(item);
}

static void
xmpp_presence(proto_tree *tree, tvbuff_t *tvb)
{
    proto_item *item = proto_tree_add_boolean(tree, hf_xmpp_presence, tvb, 0, 0, TRUE);
    PROTO_ITEM_SET_HIDDEN(item);
}

static void
xmpp_message(proto_tree *tree, tvbuff_t *tvb)
{
    proto_item *item = proto_tree_add_boolean(tree, hf_xmpp_message, tvb, 0, 0, TRUE);
    PROTO_ITEM_SET_HIDDEN(item);
}

static void
dissect_xmpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    
    xml_frame_t *xml_frame;
    gboolean is_request;

    conversation_t *conversation;
    xmpp_conv_info_t *xmpp_info;
    xmpp_transaction_t *xmpp_reqresp_trans = NULL;

    proto_tree *xmpp_tree = NULL;// *xmpp_xml_tree;
    proto_item *xmpp_item = NULL;// *xmpp_xml_item;

    xml_node_t *packet;



    if(check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "XMPP");

    //if tree == NULL then xmpp_item and xmpp_tree will also NULL
    xmpp_item = proto_tree_add_item(tree,proto_xmpp, tvb, 0, -1, FALSE);
    xmpp_tree = proto_item_add_subtree(xmpp_item, ett_xmpp);

    //xmpp_xml_item = proto_tree_add_text(xmpp_tree,tvb, 0, -1,"XML");
    //xmpp_xml_tree = proto_item_add_subtree(xmpp_xml_item, ett_xmpp_xml);


    call_dissector(xml_handle,tvb,pinfo,xmpp_tree);
    //data from XML dissector
    xml_frame = ((xml_frame_t*)pinfo->private_data)->first_child;
    packet = xml_frame_to_xml_node(xml_frame);

    conversation = find_or_create_conversation(pinfo);
    xmpp_info = conversation_get_proto_data(conversation, proto_xmpp);

    if (!xmpp_info) {
        xmpp_info = se_alloc(sizeof (xmpp_conv_info_t));
        xmpp_info->req_resp = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_req_resp");
        xmpp_info->jingle_sessions = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "xmpp_jingle_sessions");
        conversation_add_proto_data(conversation, proto_xmpp, (void *) xmpp_info);
    }

    
    if (pinfo->match_uint == pinfo->destport)
        is_request = TRUE;
    else
        is_request = FALSE;

    if(check_col(pinfo->cinfo,COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);



    if (strcmp(packet->name,"iq") == 0)
    {
        xmpp_reqresp_trans = xmpp_iq_reqresp_track(pinfo, packet, xmpp_info);
        xmpp_iq_jingle_session_track(pinfo, packet, xmpp_info);
        
    }
    
    if (tree) { /* we are being asked for details */
        proto_item *hidden_item;
        gchar *col_info= node_to_string(tvb, packet);

        if(is_request)
            hidden_item = proto_tree_add_boolean(xmpp_tree, hf_xmpp_req, tvb, 0, 0, TRUE);
        else
            hidden_item = proto_tree_add_boolean(xmpp_tree, hf_xmpp_res, tvb, 0, 0, TRUE);
      
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", is_request ? "REQ" : "RES", format_text(col_info, strlen(col_info)));

        }
        

        PROTO_ITEM_SET_HIDDEN(hidden_item);


        if(strcmp(packet->name,"iq") == 0)
        {
            xml_attr_t *attr_id;
            char *id;
            gchar *sid;


            xmpp_iq_errors_expert_info(pinfo, packet);

            xmpp_iq(xmpp_tree,tvb);

            /*Display request/response field in each iq packet*/
            if (xmpp_reqresp_trans) {

                if (xmpp_reqresp_trans->req_frame == pinfo->fd->num) {
                    if (xmpp_reqresp_trans->resp_frame) {
                        proto_item *it = proto_tree_add_uint(xmpp_tree, hf_xmpp_response_in, tvb, 0, 0, xmpp_reqresp_trans->resp_frame);
                        PROTO_ITEM_SET_GENERATED(it);
                    }

                } else {
                    if (xmpp_reqresp_trans->req_frame) {
                        proto_item *it = proto_tree_add_uint(xmpp_tree, hf_xmpp_response_to, tvb, 0, 0, xmpp_reqresp_trans->req_frame);
                        PROTO_ITEM_SET_GENERATED(it);
                    }
                }
            }

            /*Display jingle session id in jingle and their ACKs packet*/
            attr_id = g_hash_table_lookup(packet->attrs,"id");
            id = ep_strdup(attr_id->value);

            sid = se_tree_lookup_string(xmpp_info->jingle_sessions,id, EMEM_TREE_STRING_NOCASE);

            if(sid)
            {
                proto_item *it = proto_tree_add_string(xmpp_tree, hf_xmpp_jingle_session, tvb, 0, 0, sid);
                PROTO_ITEM_SET_GENERATED(it);
            }
        }

        if(strcmp(packet->name,"presence") == 0)
        {
            xmpp_presence(xmpp_tree,tvb);
        }

        if(strcmp(packet->name,"message") == 0)
        {
            xmpp_message(xmpp_tree, tvb);
        }

    }
}


void
proto_register_xmpp(void) {
    static hf_register_info hf[] = {
        { &hf_xmpp_iq,
            {
                "Iq", "xmpp.iq", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "XMPP_IQ", HFILL
            }},
            { &hf_xmpp_presence,
            {
                "Presence", "xmpp.presence", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "XMPP_PRESENCE", HFILL
            }},
            { &hf_xmpp_message,
            {
                "Message", "xmpp.message", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "XMPP_MESSAGE", HFILL
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
            { &hf_xmpp_jingle_session,
            {
                "Jingle SID", "xmpp.jingle_sid", FT_STRING, BASE_NONE, NULL, 0x0,
                "Jingle session ID", HFILL
            }}
    };

    static gint * ett[] = {
        &ett_xmpp,
        &ett_xmpp_xml,
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
