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

#define FI_RESET_FLAG(fi, flag) \
    do { \
      if (fi) \
        (fi)->flags = (fi)->flags & !(flag); \
    } while(0)

#define PROTO_ITEM_SET_VISIBLE(proto_item)       \
  do { \
    if (proto_item) \
      FI_RESET_FLAG(PITEM_FINFO(proto_item), FI_HIDDEN); \
	} while(0)

//length of attr_info array
#define AINFO_LEN(array)  (gint) sizeof(array)/sizeof(attr_info)

#define XMPP_PORT 5222

typedef struct _array_t
{
    gpointer *data;
    gint length;
} array_t;

typedef struct _attr_t{
    gchar *value;
    gint offset;
    gint length;
} attr_t;

typedef struct _data_t{
    gchar *value;

    gint offset;
    gint length;
} data_t;

typedef struct _element_t{
    gchar* name;
    GHashTable *attrs;
    GList *elements;
    data_t *data;
    proto_item *item;

    gint offset;
    gint length;
} element_t;

//informations about attributes that are displayed in proto tree
typedef struct _attr_info{
    gchar *name;
    gint hf;
    gboolean is_required;
    gboolean in_short_list;

    //function validates this attribute
    //it may impose other restrictions (e.g. validating atribut's name, ...)
    void (*val_func)(packet_info *pinfo, proto_item *item, gchar *name, gchar *value, gpointer data);
    gpointer data;
} attr_info;

typedef struct _xmpp_conv_info_t {
    emem_tree_t *req_resp;
    emem_tree_t *jingle_sessions;
} xmpp_conv_info_t;

typedef struct _xmpp_reqresp_transaction_t {
    guint32 req_frame;
    guint32 resp_frame;
} xmpp_transaction_t;

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

static gint hf_xmpp_iq_jingle_reason = -1;
static gint hf_xmpp_iq_jingle_reason_condition = -1;
static gint hf_xmpp_iq_jingle_reason_text = -1;


static gint hf_xmpp_presence = -1;
static gint hf_xmpp_message = -1;
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
static gint ett_xmpp_iq_jingle_cont_desc_payload = -1;
static gint ett_xmpp_iq_jingle_reason = -1;

static gint ett_xmpp_message = -1;
static gint ett_xmpp_presence = -1;
static gint ett_xmpp_auth = -1;
static gint ett_xmpp_challenge = -1;
static gint ett_xmpp_response = -1;
static gint ett_xmpp_success = -1;

static dissector_handle_t xml_handle = NULL;


static xmpp_transaction_t* xmpp_iq_reqresp_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);
static void xmpp_iq_jingle_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);

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
static void xmpp_iq_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

static void xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
static void xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, element_t *packet, gint hf, gint ett,
    gint hf_content, const char *col_info);

static void xmpp_unknown(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static gint
element_t_cmp(gconstpointer a, gconstpointer b)
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

    found_elements = g_list_find_custom(packet->elements, search_element, element_t_cmp);
    
    if(found_elements)
        return found_elements;
    else
        return NULL;
}


//function searches and removes element from packet.
//if element doesn't exist, NULL is returned.
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

//function searches and removes one element from packet by name
//names are taken from variable names
static element_t*
steal_element_by_names(element_t *packet, gchar **names, gint names_len)
{
    gint i;
    element_t *el = NULL;

    for(i = 0; i<names_len; i++)
    {
        if((el = steal_element_by_name(packet, names[i])))
            break;
    }

    return el;
}

static element_t*
get_first_element(element_t *packet)
{
    if(packet->elements && packet->elements->data)
        return packet->elements->data;
    else
        return NULL;
}

//Function converts xml_frame_t structure to element_t (simpler representation)
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


static gchar*
element_to_string(tvbuff_t *tvb, element_t *element)
{
    gchar *buff;

    if(tvb && tvb->initialized)
    {
        buff = ep_alloc0(element->length+1);
        tvb_memcpy(tvb,buff,element->offset,element->length);
        return buff;
    } else
    {
        return NULL;
    }
}

static void
children_foreach_hide_func(proto_node *node, gpointer data)
{
    int *i = data;
    if((*i) == 0)
        PROTO_ITEM_SET_HIDDEN(node);
    (*i)++;
}

static void
children_foreach_show_func(proto_node *node, gpointer data)
{
    int *i = data;
    if((*i) == 0)
        PROTO_ITEM_SET_VISIBLE(node);
    (*i)++;
}

static void
proto_tree_hide_first_child(proto_tree *tree)
{
    int i = 0;
    proto_tree_children_foreach(tree, children_foreach_hide_func, &i);
}

static void
proto_tree_show_first_child(proto_tree *tree)
{
    int i = 0;
    proto_tree_children_foreach(tree, children_foreach_show_func, &i);
}

/*
static void
element_tree_delete()
{
    //TODO
}
*/


static void
display_attrs(proto_tree *tree, proto_item *item, element_t *element, packet_info *pinfo, tvbuff_t *tvb, attr_info *attrs, gint n)
{
    attr_t *attr;

    gint i;
    gboolean short_list_started = FALSE;

    proto_item_append_text(item," [");
    for(i = 0; i < n; i++)
    {
        attr = g_hash_table_lookup(element->attrs, attrs[i].name);
        if(attr)
        {
            if(attrs[i].hf != -1)
                proto_tree_add_string(tree, attrs[i].hf, tvb, attr->offset, attr->length, attr->value);
            else
                proto_tree_add_text(tree, tvb, attr->offset, attr->length, "%s: %s", attrs[i].name, attr->value);

            if(attrs[i].in_short_list)
            {
                if(short_list_started)
                {
                    proto_item_append_text(item," ");
                }
                proto_item_append_text(item,"%s=%s",attrs[i].name, attr->value);
                short_list_started = TRUE;
            }

            if(attrs[i].val_func)
            {
                attrs[i].val_func(pinfo, item, attrs[i].name, attr->value, attrs[i].data);
            }
        } else if(attrs[i].is_required)
        {
            expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
                    "Required attribute \"%s\" doesn't appear in \"%s\".",attrs[i].name,
                    element->name);
        }
    }
    proto_item_append_text(item,"]");

}

//function checks that variable value is in array ((array_t)data)->data
static void
val_enum_list(packet_info *pinfo, proto_item *item, gchar *name, gchar *value, gpointer data)
{
    array_t *enums_array = data;

    gint i;
    gboolean value_in_enums = FALSE;

    gchar **enums =  (char**)enums_array->data;

    for(i = 0; i < enums_array->length; i++)
    {
        if(strcmp(value,enums[i]) == 0)
        {
            value_in_enums = TRUE;
            break;
        }
    }
    if(!value_in_enums)
    {
        expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
                "Field \"%s\" has unexpected value \"%s\"",
                name, value);
    }
}


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
        *session_element, *vcard_element, *jingle_element;

    gchar* jingle_sid;

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

     

    /*displays generated info such as req/resp tracking or jingle sid in each packet related to specified jingle session*/
    if(xmpp_info && attr_id)
    {
        jingle_sid = se_tree_lookup_string(xmpp_info->jingle_sessions, attr_id->value, EMEM_TREE_STRING_NOCASE);

        if (jingle_sid) {
            proto_item *it = proto_tree_add_string(tree, hf_xmpp_jingle_session, tvb, 0, 0, jingle_sid);
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

    gchar *ask_enums[] = {"subscribed"};
    array_t ask_enums_array = {(gpointer)ask_enums,1};

    gchar *subscription_enums[] = {"both","from","none","remove","to"};
    array_t subscription_array = {(gpointer)subscription_enums, 5};

    attr_info attrs_info[] = {
        {"jid", hf_xmpp_iq_query_item_jid, TRUE, TRUE, NULL, NULL},
        {"name", hf_xmpp_iq_query_item_name, FALSE, TRUE, NULL, NULL},
        {"node", hf_xmpp_iq_query_item_node, FALSE, TRUE, NULL, NULL},
        {"ask", hf_xmpp_iq_query_item_ask, FALSE, TRUE, val_enum_list, &ask_enums_array},
        {"approved", hf_xmpp_iq_query_item_approved, FALSE, TRUE, NULL, NULL},
        {"subscription", hf_xmpp_iq_query_item_subscription, FALSE, TRUE, val_enum_list, &subscription_array},
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

    element_t *text_element;

    attr_info attrs_info[] = {
        {"type", hf_xmpp_iq_error_type, TRUE, TRUE, NULL, NULL},
        {"code", hf_xmpp_iq_error_code, FALSE, TRUE, NULL, NULL},
        {"condition", hf_xmpp_iq_error_condition, TRUE, TRUE, NULL, NULL} /*TODO: validate list to the condition element*/
    };

    gchar *error_info;

    GList *childs = element->elements;

    attr_t *fake_condition = NULL;

    error_info = ep_strdup("Stanza error");

    error_item = proto_tree_add_item(tree, hf_xmpp_iq_error, tvb, element->offset, element->length, FALSE);
    error_tree = proto_item_add_subtree(error_item, ett_xmpp_iq_query_item);

    //loop steals defined error stanza condition from list of childs
    //and adds fake condition attribute to the element
    while(childs)
    {
        element_t *error_cond = childs->data;
        attr_t *xmlns = g_hash_table_lookup(error_cond->attrs, "xmlns");

        //child is one of the defined stanza error conditions
        if(xmlns && strcmp(xmlns->value, "urn:ietf:params:xml:ns:xmpp-stanzas") == 0)
        {
            fake_condition = ep_alloc(sizeof(attr_t));
            fake_condition->value = error_cond->name;
            fake_condition->offset = error_cond->offset;
            fake_condition->length = error_cond->length;

            g_hash_table_insert(element->attrs,"condition", fake_condition);

            element->elements = g_list_delete_link(element->elements, childs);

            error_info = ep_strdup_printf("%s: %s;", error_info, error_cond->name);
            break;
        } else
            childs = childs->next;
    }

    display_attrs(error_tree, error_item, element, pinfo, tvb, attrs_info, AINFO_LEN(attrs_info));

    while((text_element = steal_element_by_name(element, "text")) != NULL)
    {
        xmpp_iq_error_text(error_tree, tvb, text_element);

        error_info = ep_strdup_printf("%s Text: %s", error_info, text_element->data->value);
    }

    expert_add_info_format(pinfo, error_item, PI_RESPONSE_CODE, PI_NOTE,"%s", error_info);

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

    attr_info attrs_info[] = {
        {"xmlns", -1, TRUE, FALSE, NULL, NULL},
        {"action", hf_xmpp_iq_jingle_action, TRUE, TRUE, NULL, NULL},
        {"sid", hf_xmpp_iq_jingle_sid, TRUE, TRUE, NULL, NULL},
        {"initiator", hf_xmpp_iq_jingle_initiator, FALSE, TRUE, NULL, NULL},
        {"responder", hf_xmpp_iq_jingle_responder, FALSE, TRUE, NULL, NULL}
    };

    element_t *content; /*0-inf*/
    element_t *reason; /*0-1*/
    
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

    xmpp_unknown(jingle_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *content_item;
    proto_tree *content_tree;

    attr_t *creator, *name; /*REQUIRED*/
    attr_t *disposition, *senders;

    element_t *description;

    content_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_content, tvb, element->offset, element->length, FALSE);
    content_tree = proto_item_add_subtree(content_item, ett_xmpp_iq_jingle_content);

    creator = g_hash_table_lookup(element->attrs, "creator");
    name = g_hash_table_lookup(element->attrs, "name");
    disposition = g_hash_table_lookup(element->attrs, "disposition");
    senders = g_hash_table_lookup(element->attrs, "senders");

    proto_item_append_text(content_item," [");

    if(creator)
    {
        proto_tree_add_string(content_tree, hf_xmpp_iq_jingle_content_creator, tvb, creator->offset, creator->length, creator->value);
        proto_item_append_text(content_item,"creator=%s",creator->value);
    }

    if(name)
    {
        proto_tree_add_string(content_tree, hf_xmpp_iq_jingle_content_name, tvb, name->offset, name->length, name->value);
        proto_item_append_text(content_item, " name=%s",name->value);
    }

    if(disposition)
    {
        proto_tree_add_string(content_tree, hf_xmpp_iq_jingle_content_disposition, tvb, disposition->offset, disposition->length, disposition->value);
        proto_item_append_text(content_item," disposition=%s",disposition->value);
    }

    if(senders)
    {
        proto_tree_add_string(content_tree, hf_xmpp_iq_jingle_content_senders, tvb, senders->offset, senders->length, senders->value);
        proto_item_append_text(content_item," senders=%s",senders->value);
    }

    description = steal_element_by_name(element, "description");
    if(description)
        xmpp_iq_jingle_content_description(content_tree, tvb, pinfo, description);

    proto_item_append_text(content_item,"]");

    xmpp_unknown(content_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_content_description(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    attr_t *media; /*REQUIRED*/
    attr_t *xmlns, *ssrc;

    element_t *payload;

    desc_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_content_description, tvb, element->offset, element->length, FALSE);
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_iq_jingle_content_description);

    media = g_hash_table_lookup(element->attrs, "media");
    xmlns = g_hash_table_lookup(element->attrs, "xmlns");
    ssrc = g_hash_table_lookup(element->attrs, "ssrc");

    proto_item_append_text(desc_item," [");

    if(xmlns)
    {
        proto_tree_add_string(desc_tree, hf_xmpp_iq_jingle_content_description_xmlns, tvb, xmlns->offset, xmlns->length, xmlns->value);
    }
    
    if(media)
    {
        proto_tree_add_string(desc_tree, hf_xmpp_iq_jingle_content_description_media, tvb, media->offset, media->length, media->value);
        proto_item_append_text(desc_item,"media=%s", media->value);
    }

    if(ssrc)
    {
        proto_tree_add_string(desc_tree, hf_xmpp_iq_jingle_content_description_ssrc, tvb, ssrc->offset, ssrc->length, ssrc->value);
        proto_item_append_text(desc_item," ssrc=%s", ssrc->value);
    }
    proto_item_append_text(desc_item,"]");

    
    while((payload = steal_element_by_name(element, "payload-type"))!=NULL)
        xmpp_iq_jingle_cont_desc_payload(desc_tree, tvb, pinfo, payload);

    xmpp_unknown(desc_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *payload_item;
    proto_tree *payload_tree;

    attr_t *id; /*REQUIRED*/
    attr_t *channels, *clockrate, *maxptime, *name, *ptime;

    payload_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_payload, tvb, element->offset, element->length, FALSE);
    payload_tree = proto_item_add_subtree(tree, ett_xmpp_iq_jingle_cont_desc_payload);

    id = g_hash_table_lookup(element->attrs, "id");
    channels = g_hash_table_lookup(element->attrs, "channels");
    clockrate = g_hash_table_lookup(element->attrs, "clockrate");
    maxptime = g_hash_table_lookup(element->attrs, "maxptime");
    name = g_hash_table_lookup(element->attrs, "name");
    ptime = g_hash_table_lookup(element->attrs, "ptime");

    

    xmpp_unknown(payload_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *reason_item;
    proto_tree *reason_tree;

    element_t *condition; /*1?*/
    element_t *text; /*0-1*/

    gchar *reasons[] = { "success", "busy", "failed-application", "cancel", "connectivity-error",
        "decline", "expired", "failed-transport", "general-error", "gone", "incompatible-parameters",
        "media-error", "security-error", "timeout", "unsupported-applications", "unsupported-transports"};

    reason_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_reason, tvb, element->offset, element->length, FALSE);
    reason_tree = proto_item_add_subtree(reason_item, ett_xmpp_iq_jingle_reason);


    if((condition = steal_element_by_names(element, reasons, sizeof(reasons)/sizeof(gchar*)))!=NULL)
    {
        proto_tree_add_string(reason_tree, hf_xmpp_iq_jingle_reason_condition, tvb, condition->offset, condition->length, condition->name);
    } else if((condition = steal_element_by_name(element, "alternative-session"))!=NULL)
    {
        /*TODO*/
    }

    if((text = steal_element_by_name(element, "text"))!=NULL)
    {
        proto_tree_add_string(reason_tree, hf_xmpp_iq_jingle_reason_text, tvb, text->offset, text->length, text->data->value);
    }

    xmpp_unknown(reason_tree, tvb, pinfo, element);
}

static void
xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *presence_item;
    proto_tree *presence_tree;

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "PRESENCE");

    presence_item = proto_tree_add_item(tree, hf_xmpp_presence, tvb, packet->offset, packet->length, FALSE);
    presence_tree = proto_item_add_subtree(presence_item, ett_xmpp_presence);

    xmpp_unknown(presence_tree, tvb, pinfo, packet);
}

static void
xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    proto_item *message_item;
    proto_tree *message_tree;

    if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "MESSAGE");

    message_item = proto_tree_add_item(tree, hf_xmpp_message, tvb, packet->offset, packet->length, FALSE);
    message_tree = proto_item_add_subtree(message_item, ett_xmpp_message);

    xmpp_unknown(message_tree, tvb, pinfo, packet);
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
        conversation_add_proto_data(conversation, proto_xmpp, (void *) xmpp_info);
    }

    
    if (pinfo->match_uint == pinfo->destport)
        is_request = TRUE;
    else
        is_request = FALSE;

    if (strcmp(packet->name,"iq") == 0)
    {
        xmpp_iq_reqresp_track(pinfo, packet, xmpp_info);
        xmpp_iq_jingle_session_track(pinfo, packet, xmpp_info);
        
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
            { &hf_xmpp_presence,
            {
                "PRESENCE", "xmpp.presence", FT_NONE, BASE_NONE, NULL, 0x0,
                "presence", HFILL
            }},
            { &hf_xmpp_message,
            {
                "MESSAGE", "xmpp.message", FT_NONE, BASE_NONE, NULL, 0x0,
                "message", HFILL
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
        &ett_xmpp_iq_bind,
        &ett_xmpp_iq_vcard,
        &ett_xmpp_iq_jingle,
        &ett_xmpp_iq_jingle_content,
        &ett_xmpp_iq_jingle_content_description,
        &ett_xmpp_iq_jingle_cont_desc_payload,
        &ett_xmpp_iq_jingle_reason,
        &ett_xmpp_message,
        &ett_xmpp_presence,
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
