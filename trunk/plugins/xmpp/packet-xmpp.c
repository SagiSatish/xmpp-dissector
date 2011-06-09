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

typedef struct _attr_t{
    gchar *value;
    gint offset;
    gint length;
} attr_t;

typedef struct _xml_data_t{
    gchar *value;

    gint offset;
    gint length;
} data_t;

typedef struct _packet_t{
    gchar* name;
    GHashTable *attrs;
    GList *elements;
    data_t *data;
    proto_item *item;

    gint offset;
    gint length;
} element_t;

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

static gint hf_xmpp_iq_query_identity = -1;
static gint hf_xmpp_iq_query_identity_category = -1;
static gint hf_xmpp_iq_query_identity_type = -1;
static gint hf_xmpp_iq_query_identity_name = -1;
static gint hf_xmpp_iq_query_identity_lang = -1;

static gint hf_xmpp_iq_query_feature = -1;

static gint hf_xmpp_iq_error = -1;
static gint hf_xmpp_iq_error_type = -1;
static gint hf_xmpp_iq_error_code = -1;

static gint hf_xmpp_presence = -1;
static gint hf_xmpp_message = -1;

static gint hf_xmpp_req = -1;
static gint hf_xmpp_res = -1;
static gint hf_xmpp_response_in = -1;
static gint hf_xmpp_response_to = -1;
static gint hf_xmpp_jingle_session = -1;

static gint ett_xmpp = -1;
static gint ett_xmpp_iq = -1;
static gint ett_xmpp_xml = -1;
static gint ett_xmpp_iq_query = -1;
static gint ett_xmpp_iq_query_item = -1;
static gint ett_xmpp_iq_query_identity = -1;
static gint ett_xmpp_iq_query_feature = -1;

static gint ett_xmpp_iq_error = -1;

static dissector_handle_t xml_handle = NULL;


static xmpp_transaction_t* xmpp_iq_reqresp_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);
static void xmpp_iq_jingle_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);
static void xmpp_iq_errors_expert_info(packet_info *pinfo, element_t *packet);

static void xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_iq_query(proto_tree *tree,  tvbuff_t *tvb, element_t *element);
static void xmpp_iq_query_item(proto_tree *tree, tvbuff_t *tvb, element_t *element);
static void xmpp_iq_query_identity(proto_tree *tree, tvbuff_t *tvb, element_t *element);
static void xmpp_iq_query_feature(proto_tree *tree, tvbuff_t *tvb, element_t *element);

static void xmpp_iq_error(proto_tree *tree, tvbuff_t *tvb, element_t *element);

static void xmpp_presence(proto_tree *tree, tvbuff_t *tvb);

static void xmpp_message(proto_tree *tree, tvbuff_t *tvb);

static gint
xml_node_cmp(gconstpointer a, gconstpointer b)
{
    return strcmp(((element_t*)a)->name,((element_t*)b)->name);
}

static GList*
find_element_by_name(element_t *packet,const gchar *name)
{
    GList *found_elements;
    element_t *search_element;

    //create fake elementonly with name
    search_element = ep_alloc(sizeof(element_t));
    search_element->name = ep_strdup(name);

    found_elements = g_list_find_custom(packet->elements, search_element, xml_node_cmp);
    
    if(found_elements)
        return found_elements;
    else
        return NULL;
}


//Function removes element from packet and returns it
//If element doesn't exist, NULL is returned
static element_t*
steal_element_by_name(element_t *packet, gchar *name)
{
    GList *element_l;
    element_t *element = NULL;

    element_l = find_element_by_name(packet, name);

    if(element_l)
    {
        element = element_l->data;
        packet->elements = g_list_delete_link(packet->elements, element_l);
    }

    return element;
    
}

//it converts xml_frame_t structure to element_t (simpler representation)
static element_t*
xml_frame_to_element_t(xml_frame_t *xml_frame)
{
    static gint start_offset = -1;
    xml_frame_t *child;
    element_t *node = ep_alloc0(sizeof(element_t));


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

                attr_t *attr = ep_alloc(sizeof(attr_t));
                attr->length = 0;
                attr->offset = 0;

                if (child->value != NULL && child->value->initialized) {
                    l = tvb_reported_length(child->value);
                    value = ep_alloc0(l + 1);
                    tvb_memcpy(child->value, value, 0, l);
                }

                if(child->item)
                {
                    attr->offset = child->item->finfo->start - start_offset;
                    attr->length = child->item->finfo->length;
                }
                attr->value = value;

                g_hash_table_insert(node->attrs,(gpointer)child->name_orig_case,(gpointer)attr);
            }
            else if( child->type == XML_FRAME_CDATA)
            {
                data_t *data = NULL;
                gint l;
                gchar* value = NULL;

                data = ep_alloc(sizeof(data_t));
                data->length = 0;
                data->offset = 0;

                if (child->value != NULL && child->value->initialized) {
                    l = tvb_reported_length(child->value);
                    value = ep_alloc0(l + 1);
                    tvb_memcpy(child->value, value, 0, l);
                }

                data->value = value;

                if(child->item)
                {
                    data->offset = child->item->finfo->start - start_offset;
                    data->length = child->item->finfo->length;
                }
                node->data = data;
            }
        } else
        {
            node->elements = g_list_append(node->elements,(gpointer)xml_frame_to_element_t(child));
        }
        
        child = child->next_sibling;
    }
    return node;
}


/*
static gchar*
node_to_string(tvbuff_t *tvb, element_t *node)
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
*/

/*
static void
xml_tree_delete()
{
    //TODO
}
*/

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
xmpp_iq_jingle_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info)
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
xmpp_iq_errors_expert_info(packet_info *pinfo, element_t *packet)
{
    attr_t *attr_type;

    attr_type = g_hash_table_lookup(packet->attrs, "type");
    if(attr_type && strcmp(attr_type->value,"error")==0)
    {
        GList *error_l = find_element_by_name(packet,"error");

        element_t *error = error_l?error_l->data:NULL;

        if(error)
        {
            gchar *buff= ep_strdup("Stanza error");
            GList *child_elem = error->elements;

            while(child_elem)
            {
                element_t *node = child_elem->data;

                buff = ep_strdup_printf("%s; %s",buff,node->name);
                if(node->data)
                {
                    data_t *data = node->data;
                    buff = ep_strdup_printf("%s:%s",buff,data->value);
                }

                child_elem = child_elem->next;
            }

            expert_add_info_format(pinfo, error->item, PI_RESPONSE_CODE, PI_NOTE,"%s", buff);
        }
    }
}

static void
xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *xmpp_iq_item;
    proto_tree *xmpp_iq_tree;

    attr_t *attr_id, *attr_type, *attr_from, *attr_to;

    element_t *query_element = NULL;
    element_t  *error_element = NULL;

    attr_id = g_hash_table_lookup(packet->attrs,"id");
    attr_type = g_hash_table_lookup(packet->attrs,"type");
    attr_from = g_hash_table_lookup(packet->attrs,"from");
    attr_to = g_hash_table_lookup(packet->attrs,"to");

    xmpp_iq_item = proto_tree_add_item(tree, hf_xmpp_iq, tvb, packet->offset, packet->length, TRUE);
    xmpp_iq_tree = proto_item_add_subtree(xmpp_iq_item,ett_xmpp_iq);

    proto_item_append_text(xmpp_iq_item," [");
    if(attr_id)
    {
        proto_tree_add_string(xmpp_iq_tree, hf_xmpp_iq_id, tvb, attr_id->offset, attr_id->length, attr_id->value);
        proto_item_append_text(xmpp_iq_item, "id=%s", attr_id->value);
    }
    if(attr_type)
    {
        proto_tree_add_string(xmpp_iq_tree, hf_xmpp_iq_type, tvb, attr_type->offset, attr_type->length, attr_type->value);
        proto_item_append_text(xmpp_iq_item, " type=%s", attr_type->value);
    }

    if(attr_from)
    {
        proto_tree_add_string(xmpp_iq_tree, hf_xmpp_iq_from, tvb, attr_from->offset, attr_from->length, attr_from->value);
        proto_item_append_text(xmpp_iq_item, " from=%s", attr_from->value);
    }
    if(attr_to)
    {
        proto_tree_add_string(xmpp_iq_tree, hf_xmpp_iq_to, tvb, attr_to->offset, attr_to->length, attr_to->value);
        proto_item_append_text(xmpp_iq_item, " to=%s", attr_to->value);
    }

    proto_item_append_text(xmpp_iq_item,"]");


    if (check_col(pinfo->cinfo, COL_INFO))
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ %s", attr_type?attr_type->value:"");

    if((query_element = steal_element_by_name(packet,"query")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ QUERY %s", attr_type?attr_type->value:"");
        }
        xmpp_iq_query(xmpp_iq_tree,tvb,query_element);
    }

    if((error_element = steal_element_by_name(packet, "error")) != NULL)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "IQ ERROR %s", attr_type?attr_type->value:"");
        }
        xmpp_iq_error(xmpp_iq_tree, tvb, error_element);
    }
}


static void
xmpp_iq_query(proto_tree *tree,  tvbuff_t *tvb, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_t *xmlns, *node;

    element_t *item_element, *identity_element, *feature_element;

    gboolean has_attribs;
    has_attribs = FALSE;

    query_item = proto_tree_add_item(tree, hf_xmpp_iq_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_iq_query);

    xmlns = g_hash_table_lookup(element->attrs,"xmlns");
    node = g_hash_table_lookup(element->attrs,"node");

    if(xmlns || node)
        has_attribs = TRUE;

    if(has_attribs)
         proto_item_append_text(query_item, " [");

    if(xmlns)
    {
        proto_tree_add_string(query_tree, hf_xmpp_iq_query_xmlns, tvb, xmlns->offset, xmlns->length, xmlns->value);
        proto_item_append_text(query_item, "xmlns=%s", xmlns->value);
    }
    if(node)
    {
        proto_tree_add_string(query_tree, hf_xmpp_iq_query_node, tvb, node->offset, node->length, node->value);
        proto_item_append_text(query_item, " node=%s", node->value);
    }

    if(has_attribs)
         proto_item_append_text(query_item, "]");

    while((item_element = steal_element_by_name(element, "item")) != NULL)
    {
        xmpp_iq_query_item(query_tree, tvb, item_element);
    }

    while((identity_element = steal_element_by_name(element, "identity")) != NULL)
    {
        xmpp_iq_query_identity(query_tree, tvb, identity_element);
    }

    while((feature_element = steal_element_by_name(element, "feature")) != NULL)
    {
        xmpp_iq_query_feature(query_tree, tvb, feature_element);
    }
}

static void
xmpp_iq_query_item(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    attr_t *jid, *name, *subscription, *ask;
    element_t *group;

    item_item = proto_tree_add_item(tree, hf_xmpp_iq_query_item, tvb, element->offset, element->length, FALSE);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_iq_query_item);

    jid = g_hash_table_lookup(element->attrs, "jid");
    name = g_hash_table_lookup(element->attrs, "name");
    subscription = g_hash_table_lookup(element->attrs, "subscription");
    ask = g_hash_table_lookup(element->attrs, "ask");

    group = steal_element_by_name(element,"group");

    proto_item_append_text(item_item, " [");
    if(jid)
    {
        proto_tree_add_string(item_tree, hf_xmpp_iq_query_item_jid, tvb, jid->offset, jid->length, jid->value);
        proto_item_append_text(item_item, "jid=%s", jid->value);
    }
    if(name)
    {
         proto_tree_add_string(item_tree, hf_xmpp_iq_query_item_name, tvb, name->offset, name->length, name->value);
         proto_item_append_text(item_item, " name=%s", name->value);
    }
    if(subscription)
    {
         proto_tree_add_string(item_tree, hf_xmpp_iq_query_item_subscription, tvb, subscription->offset, subscription->length, subscription->value);
         proto_item_append_text(item_item, " subscription=%s", subscription->value);
    }
    if(ask)
    {
         proto_tree_add_string(item_tree, hf_xmpp_iq_query_item_ask, tvb, ask->offset, ask->length, ask->value);
         proto_item_append_text(item_item, " ask=%s", ask->value);
    }
    if(group)
    {
         proto_tree_add_string(item_tree, hf_xmpp_iq_query_item_group, tvb, group->data->offset, group->data->length, group->data->value);
         proto_item_append_text(item_item, " group=%s", group->data->value);
    }
    proto_item_append_text(item_item, "]");
}

static void
xmpp_iq_query_identity(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    proto_item *identity_item;
    proto_tree *identity_tree;

    attr_t *category, *name, *type, *lang;

    identity_item = proto_tree_add_item(tree, hf_xmpp_iq_query_identity, tvb, element->offset, element->length, FALSE);
    identity_tree = proto_item_add_subtree(identity_item, ett_xmpp_iq_query_identity);

    type = g_hash_table_lookup(element->attrs, "type");
    name = g_hash_table_lookup(element->attrs, "name");
    category = g_hash_table_lookup(element->attrs, "category");
    lang = g_hash_table_lookup(element->attrs, "xml:lang");

    proto_item_append_text(identity_item, " [");
    if(category)
    {
        proto_tree_add_string(identity_tree, hf_xmpp_iq_query_identity_category, tvb, category->offset, category->length, category->value);
        proto_item_append_text(identity_item, "category=%s", category->value);
    }
    if(type)
    {
        proto_tree_add_string(identity_tree, hf_xmpp_iq_query_identity_type, tvb, type->offset, type->length, type->value);
        proto_item_append_text(identity_item, " type=%s", type->value);
    }
    if(name)
    {
        proto_tree_add_string(identity_tree, hf_xmpp_iq_query_identity_name, tvb, name->offset, name->length, name->value);
        proto_item_append_text(identity_item, " name=%s", name->value);
    }
    if(lang)
    {
        proto_tree_add_string(identity_tree, hf_xmpp_iq_query_identity_lang, tvb, lang->offset, lang->length, lang->value);
        proto_item_append_text(identity_item, " lang=%s", lang->value);
    }
    proto_item_append_text(identity_item, "]");
    
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
xmpp_iq_error(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    proto_item *error_item;
    proto_tree *error_tree;

    attr_t *type, *code;

    error_item = proto_tree_add_item(tree, hf_xmpp_iq_error, tvb, element->offset, element->length, FALSE);
    error_tree = proto_item_add_subtree(error_item, ett_xmpp_iq_query_item);

    type = g_hash_table_lookup(element->attrs, "type");
    code = g_hash_table_lookup(element->attrs,"code");

    proto_item_append_text(error_item, "[");
    if(type)
    {
        proto_tree_add_string(error_tree, hf_xmpp_iq_error_type, tvb, type->offset, type->length, type->value);
        proto_item_append_text(error_item, " type: %s;", type->value);
    }
    if(code)
    {
        proto_tree_add_string(error_tree, hf_xmpp_iq_error_code, tvb, code->offset, code->length, code->value);
        proto_item_append_text(error_item, " code: %s;", code->value);
    }
    proto_item_append_text(error_item, " ]");
    
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

    element_t *packet;



    if(check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "XMPP");

    if (check_col(pinfo->cinfo, COL_INFO))
            col_clear(pinfo->cinfo, COL_INFO);

    //if tree == NULL then xmpp_item and xmpp_tree will also NULL
    xmpp_item = proto_tree_add_item(tree,proto_xmpp, tvb, 0, -1, FALSE);
    xmpp_tree = proto_item_add_subtree(xmpp_item, ett_xmpp);

    //xmpp_xml_item = proto_tree_add_text(xmpp_tree,tvb, 0, -1,"XML");
    //xmpp_xml_tree = proto_item_add_subtree(xmpp_xml_item, ett_xmpp_xml);


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
        conversation_add_proto_data(conversation, proto_xmpp, (void *) xmpp_info);
    }

    
    if (pinfo->match_uint == pinfo->destport)
        is_request = TRUE;
    else
        is_request = FALSE;

    if (strcmp(packet->name,"iq") == 0)
    {
        xmpp_reqresp_trans = xmpp_iq_reqresp_track(pinfo, packet, xmpp_info);
        xmpp_iq_jingle_session_track(pinfo, packet, xmpp_info);
        
    }
    
    if (tree) { /* we are being asked for details */
        proto_item *hidden_item;
        //gchar *col_info= node_to_string(tvb, packet);

        if(is_request)
            hidden_item = proto_tree_add_boolean(xmpp_tree, hf_xmpp_req, tvb, 0, 0, TRUE);
        else
            hidden_item = proto_tree_add_boolean(xmpp_tree, hf_xmpp_res, tvb, 0, 0, TRUE);
      
/*
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", is_request ? "REQ" : "RES", format_text(col_info, strlen(col_info)));

        }
*/
        

        PROTO_ITEM_SET_HIDDEN(hidden_item);


        if(strcmp(packet->name,"iq") == 0)
        {
            attr_t *attr_id;
            char *id;
            gchar *sid;


            xmpp_iq_errors_expert_info(pinfo, packet);

            xmpp_iq(xmpp_tree,tvb, pinfo, packet);

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
                "IQ", "xmpp.iq", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq stanza", HFILL
            }},
            { &hf_xmpp_iq_id,
            {
                "id", "xmpp.iq.id", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza id", HFILL
            }},
            { &hf_xmpp_iq_type,
            {
                "type", "xmpp.iq.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza type", HFILL
            }},
             { &hf_xmpp_iq_from,
            {
                "from", "xmpp.iq.from", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza from", HFILL
            }},
             { &hf_xmpp_iq_to,
            {
                "to", "xmpp.iq.to", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza to", HFILL
            }},
            { &hf_xmpp_iq_query,
            {
                "QUERY", "xmpp.iq.query", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq stanza query", HFILL
            }},
            { &hf_xmpp_iq_query_xmlns,
            {
                "xmlns", "xmpp.iq.query.xmlns", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query xmlns", HFILL
            }},
            { &hf_xmpp_iq_query_node,
            {
                "node", "xmpp.iq.query.node", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query node", HFILL
            }},
            { &hf_xmpp_iq_query_item,
            {
                "ITEM", "xmpp.iq.query.item", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq stanza query item", HFILL

            }},
            { &hf_xmpp_iq_query_item_jid,
            {
                "jid", "xmpp.iq.query.item.jid", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query item jid", HFILL

            }},
            { &hf_xmpp_iq_query_item_name,
            {
                "name", "xmpp.iq.query.item.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query item name", HFILL
            }},
            { &hf_xmpp_iq_query_item_subscription,
            {
                "subscription", "xmpp.iq.query.item.subscription", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query item subscription", HFILL
            }},
            { &hf_xmpp_iq_query_item_ask,
            {
                "ask", "xmpp.iq.query.item.ask", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query item ask", HFILL
            }},
            { &hf_xmpp_iq_query_item_group,
            {
                "group", "xmpp.iq.query.item.group", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query item group", HFILL

            }},
            { &hf_xmpp_iq_query_identity,
            {
                "IDENTITY", "xmpp.iq.query.identity", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq stanza query identity", HFILL

            }},
            { &hf_xmpp_iq_query_identity_category,
            {
                "category", "xmpp.iq.query.identity.category", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query identity category", HFILL

            }},
            { &hf_xmpp_iq_query_identity_type,
            {
                "type", "xmpp.iq.query.identity.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query identity type", HFILL

            }},
            { &hf_xmpp_iq_query_identity_name,
            {
                "name", "xmpp.iq.query.identity.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query identity name", HFILL

            }},
            { &hf_xmpp_iq_query_identity_lang,
            {
                "lang", "xmpp.iq.query.identity.lang", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query identity lang", HFILL

            }},
            { &hf_xmpp_iq_query_feature,
            {
                "FEATURE", "xmpp.iq.query.feature", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza query feature", HFILL

            }},
            { &hf_xmpp_iq_error,
            {
                "ERROR", "xmpp.iq.error", FT_NONE, BASE_NONE, NULL, 0x0,
                "iq stanza error", HFILL
            }},
            { &hf_xmpp_iq_error_code,
            {
                "code", "xmpp.iq.error.code", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza error code", HFILL

            }},
            
            { &hf_xmpp_iq_error_type,
            {
                "type", "xmpp.iq.error.type", FT_STRING, BASE_NONE, NULL, 0x0,
                "iq stanza error type", HFILL

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
        &ett_xmpp_iq,
        &ett_xmpp_iq_query,
        &ett_xmpp_iq_query_item,
        &ett_xmpp_iq_query_identity,
        &ett_xmpp_iq_query_feature,
        &ett_xmpp_iq_error,
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
