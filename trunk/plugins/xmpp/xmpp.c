#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <glib.h>
#include <stdio.h>

#include <epan/conversation.h>
#include <epan/proto.h>
#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/expert.h>
#include <epan/tvbuff.h>
#include <epan/tvbparse.h>

#include <epan/dissectors/packet-xml.h>

#include <plugins/xmpp/packet-xmpp.h>
#include <plugins/xmpp/xmpp.h>

#include <epan/strutil.h>

void
xmpp_iq_reqresp_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    xmpp_transaction_t *xmpp_trans = NULL;

    attr_t *attr_id;
    char *id;

    attr_id = get_attr(packet, "id");
    DISSECTOR_ASSERT(attr_id);
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
}

void
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


        attr_id = get_attr(packet, "id");
        DISSECTOR_ASSERT(attr_id);
        
        se_id = se_strdup(attr_id->value);

        attr_sid = get_attr(jingle_packet, "sid");
        DISSECTOR_ASSERT(attr_sid);
        
        se_sid = se_strdup(attr_sid->value);

        se_tree_insert_string(xmpp_info->jingle_sessions, se_id, (void*) se_sid, EMEM_TREE_STRING_NOCASE);
    }
}

void
xmpp_gtalk_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    element_t *gtalk_packet;
    GList *gtalk_packet_l;

    gtalk_packet_l = find_element_by_name(packet,"session");
    gtalk_packet = gtalk_packet_l?gtalk_packet_l->data:NULL;


    if (gtalk_packet && !pinfo->fd->flags.visited) {
        attr_t *attr_id;
        attr_t *attr_sid;

        char *se_id;
        char *se_sid;

        attr_t *xmlns = get_attr(gtalk_packet, "xmlns");
        if(xmlns && strcmp(xmlns->value,"http://www.google.com/session") != 0)
            return;


        attr_id = get_attr(packet, "id");
        DISSECTOR_ASSERT(attr_id);

        se_id = se_strdup(attr_id->value);

        attr_sid = get_attr(gtalk_packet, "id");
        DISSECTOR_ASSERT(attr_sid);
        se_sid = se_strdup(attr_sid->value);

        se_tree_insert_string(xmpp_info->gtalk_sessions, se_id, (void*) se_sid, EMEM_TREE_STRING_NOCASE);
    }
}

void
xmpp_ibb_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info)
{
    element_t *ibb_packet = NULL;
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


        attr_id = get_attr(packet, "id");
        attr_sid = get_attr(ibb_packet, "sid");
        if(attr_id && attr_sid)
        {
            se_id = se_strdup(attr_id->value);
            se_sid = se_strdup(attr_sid->value);
            se_tree_insert_string(xmpp_info->ibb_sessions, se_id, (void*) se_sid, EMEM_TREE_STRING_NOCASE);
        }
    }
}

static void
xmpp_unknown_items(proto_tree *tree, tvbuff_t *tvb, element_t *element, guint level)
{
    GList *keys = g_hash_table_get_keys(element->attrs);
    GList *childs = element->elements;
    
    GList *keys_head = keys;

    gboolean short_list_started = FALSE;
    proto_item* parent_item = proto_tree_get_parent(tree);


    DISSECTOR_ASSERT( level < ETT_UNKNOWN_LEN );

    while(keys)
    {
        attr_t *attr = get_attr(element, (const gchar*)keys->data);
        if(attr)
        {
            if(!short_list_started)
                proto_item_append_text(parent_item, " [");
            else
                proto_item_append_text(parent_item, " ");
            proto_item_append_text(parent_item, "%s=\"%s\"", (gchar*)keys->data,attr->value);

            proto_tree_add_text(tree, tvb, attr->offset, attr->length, "%s: %s",(gchar*)keys->data,attr->value);
            short_list_started = TRUE;
        }
        keys = keys->next;
    }

    if(short_list_started)
        proto_item_append_text(parent_item, "]");

    g_list_free(keys_head);

    if(element->data)
    {
        proto_tree_add_text(tree, tvb, element->data->offset, element->data->length, "CDATA: %s",element->data->value);
    }

    while(childs)
    {
        element_t *child = childs->data;
        proto_item *child_item = proto_tree_add_text(tree, tvb, child->offset, child->length, "%s", ep_string_upcase(child->name));
        proto_tree *child_tree = proto_item_add_subtree(child_item, ett_unknown[level]);

        if(child->default_ns_abbrev)
            proto_item_append_text(child_item, "(%s)", child->default_ns_abbrev);

        xmpp_unknown_items(child_tree, tvb, child, level +1);

        childs = childs->next;
    }
}

void
xmpp_unknown(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    GList *childs = element->elements;

    /*element has unrecognized elements*/
    while(childs)
    {
        element_t *child = childs->data;
        if(!child->was_read)
        {
            proto_item *unknown_item = proto_tree_add_string_format(tree,
                    hf_xmpp_unknown, tvb, child->offset, child->length, child->name,
                    "%s", ep_string_upcase(child->name));

            proto_tree *unknown_tree = proto_item_add_subtree(unknown_item, ett_unknown[0]);

            col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", ep_string_upcase(child->name));

            if(child->default_ns_abbrev)
                proto_item_append_text(unknown_item,"(%s)",child->default_ns_abbrev);

            xmpp_unknown_items(unknown_tree, tvb, child, 1);
#ifdef XMPP_DEBUG
            proto_item_append_text(unknown_item, " [UNKNOWN]");

            expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_NOTE,"Unknown element: %s", child->name);
#endif
        }
        childs = childs->next;
    }
}

void
xmpp_cdata(proto_tree *tree, tvbuff_t *tvb, element_t *element, gint hf)
{
    if(element->data)
{
        if (hf == -1) {
            proto_tree_add_text(tree, tvb, element->data->offset, element->data->length, "CDATA: %s", element->data->value);
        } else {
            proto_tree_add_string(tree, hf, tvb, element->data->offset, element->data->length, element->data->value);
        }
    } else
    {
        if (hf == -1) {
            proto_tree_add_text(tree, tvb, 0, 0, "CDATA: (empty)");
        } else {
            proto_tree_add_string(tree, hf, tvb, 0, 0, "");
        }
    }
}

array_t*
ep_init_array_t(const gchar** array, gint len)
{
    array_t *result;

    result = ep_alloc(sizeof(array_t));
    result->data = (const gpointer) array;
    result->length = len;
    
    return result;
}

attr_t*
ep_init_attr_t(gchar *value, gint offset, gint length)
{
    attr_t *result;
    result = ep_alloc(sizeof(attr_t));
    result->value = value;
    result->offset = offset;
    result->length = length;
    result->name = NULL;

    return result;
}

gchar*
ep_string_upcase(const gchar* string)
{
    gint len = strlen(string);
    gint i;
    gchar* result = ep_alloc0(len+1);
    for(i=0; i<len; i++)
    {
        result[i] = string[i];

        if(string[i]>='a' && string[i]<='z')
            result[i]-='a'-'A';

    }
    return result;
}

gint
element_t_cmp(gconstpointer a, gconstpointer b)
{
    gint result = strcmp(((element_t*)a)->name,((element_t*)b)->name);

    if(result == 0 && ((element_t*)a)->was_read)
        result = -1;

    return result;
}

GList*
find_element_by_name(element_t *packet,const gchar *name)
{
    GList *found_elements;
    element_t *search_element;

    /*create fake elementonly with name*/
    search_element = ep_alloc(sizeof(element_t));
    search_element->name = ep_strdup(name);

    found_elements = g_list_find_custom(packet->elements, search_element, element_t_cmp);

    if(found_elements)
        return found_elements;
    else
        return NULL;
}


/*function searches and removes element from packet.
  if element doesn't exist, NULL is returned.*/
element_t*
steal_element_by_name(element_t *packet,const gchar *name)
{
    GList *element_l;
    element_t *element = NULL;

    element_l = find_element_by_name(packet, name);

    if(element_l)
    {
        element = element_l->data;
/*
        packet->elements = g_list_delete_link(packet->elements, element_l);
*/
        element->was_read = TRUE;
    }

    return element;

}

/*function searches and removes one element from packet by name
  names are taken from variable names*/
element_t*
steal_element_by_names(element_t *packet, const gchar **names, gint names_len)
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

element_t*
steal_element_by_attr(element_t *packet, const gchar *attr_name, const gchar *attr_value)
{
    GList *childs = packet->elements;
    element_t *result = NULL;

    while (childs) {
        element_t *child_elem = childs->data;
        attr_t *attr = get_attr(child_elem, attr_name);

/*
        child is one of the defined stanza error conditions
*/
        if (!child_elem->was_read && attr && strcmp(attr->value, attr_value) == 0) {

            result = childs->data;
/*
            packet->elements = g_list_delete_link(packet->elements, childs);
*/
            result->was_read = TRUE;
            
            break;
        } else
            childs = childs->next;
    }

    return result;
}

element_t*
steal_element_by_name_and_attr(element_t *packet, const gchar *name, const gchar *attr_name, const gchar *attr_value)
{
    GList *childs = packet->elements;
    element_t *result = NULL;

    while (childs) {
        element_t *child_elem = childs->data;
        attr_t *attr = get_attr(child_elem, attr_name);

/*
        child is one of the defined stanza error conditions
*/
        if (!child_elem->was_read && attr && strcmp(child_elem->name, name) == 0 && strcmp(attr->value, attr_value) == 0) {

            result = childs->data;
/*
            packet->elements = g_list_delete_link(packet->elements, childs);
*/
            result->was_read = TRUE;

            break;
        } else
            childs = childs->next;
    }
    return result;
}

element_t*
get_first_element(element_t *packet)
{
    if(packet->elements && packet->elements->data)
        return packet->elements->data;
    else
        return NULL;
}

/*
Function converts xml_frame_t structure to element_t (simpler representation)
*/
element_t*
xml_frame_to_element_t(xml_frame_t *xml_frame, element_t *parent, tvbuff_t *tvb)
{
    xml_frame_t *child;
    element_t *node = ep_alloc0(sizeof(element_t));

    tvbparse_wanted_t *want_ignore, *want_name, *want_scoped_name;
    tvbparse_t* tt;
    tvbparse_elem_t* elem;

    node->attrs = g_hash_table_new(g_str_hash, g_str_equal);
    node->elements = NULL;
    node->data = NULL;
    node->was_read = FALSE;
    node->default_ns_abbrev = NULL;

    node->name = ep_strdup(xml_frame->name_orig_case);
    node->offset = 0;
    node->length = 0;

    node->namespaces = g_hash_table_new(g_str_hash, g_str_equal);
    if(parent)
    {
        copy_hash_table(parent->namespaces, node->namespaces);
    } else
    {
        g_hash_table_insert(node->namespaces, "", "jabber:client");
    }

    if(xml_frame->item != NULL)
    {
        node->length = xml_frame->item->finfo->length;
    }
    
    node->offset = xml_frame->start_offset;

    /*looking for element's names that looks like ns:tag_name*/
    want_ignore = tvbparse_chars(-1,1,0," \t\r\n</",NULL,NULL,NULL);
    want_name = tvbparse_chars(-1,1,0,"abcdefghijklmnopqrstuvwxyz.-_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",NULL,NULL,NULL);
    want_scoped_name = tvbparse_set_seq(-1, NULL, NULL, NULL,
							       want_name,
							       tvbparse_char(-1,":",NULL,NULL,NULL),
							       want_name,
							       NULL);
    tt = tvbparse_init(tvb,node->offset,-1,NULL,want_ignore);

    if((elem = tvbparse_get(tt,want_scoped_name))!=NULL)
    {
        node->default_ns_abbrev = tvb_get_ephemeral_string(elem->sub->tvb, elem->sub->offset, elem->sub->len);
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
                gchar *xmlns_needle = NULL;

                attr_t *attr = ep_alloc(sizeof(attr_t));
                attr->length = 0;
                attr->offset = 0;
                
                if (child->value != NULL) {
                    l = tvb_reported_length(child->value);
                    value = ep_alloc0(l + 1);
                    tvb_memcpy(child->value, value, 0, l);
                }

                if(child->item)
                {
                    attr->length = child->item->finfo->length;
                }
                
                attr->offset = child->start_offset;
                attr->value = value;
                attr->name = ep_strdup(child->name_orig_case);

                g_hash_table_insert(node->attrs,(gpointer)attr->name,(gpointer)attr);

                /*checking that attr->name looks like xmlns:ns*/
                xmlns_needle = epan_strcasestr(attr->name, "xmlns");
                
                if(xmlns_needle == attr->name)
                {
                    if(attr->name[5] == ':' && strlen(attr->name) > 6)
                    {
                        g_hash_table_insert(node->namespaces, (gpointer)ep_strdup(&attr->name[6]), (gpointer)ep_strdup(attr->value));
                    } else if(attr->name[5] == '\0')
                    {
                        g_hash_table_insert(node->namespaces, "", (gpointer)ep_strdup(attr->value));
                    }
                }


            }
            else if( child->type == XML_FRAME_CDATA)
            {
                data_t *data = NULL;
                gint l;
                gchar* value = NULL;

                data = ep_alloc(sizeof(data_t));
                data->length = 0;
                data->offset = 0;

                if (child->value != NULL) {
                    l = tvb_reported_length(child->value);
                    value = ep_alloc0(l + 1);
                    tvb_memcpy(child->value, value, 0, l);
                }

                data->value = value;

                if(child->item)
                {
                    data->length = child->item->finfo->length;
                }
                data->offset = child->start_offset;
                node->data = data;
            }
        } else
        {
            node->elements = g_list_append(node->elements,(gpointer)xml_frame_to_element_t(child, node,tvb));
        }

        child = child->next_sibling;
    }
    return node;
}

void
element_t_tree_free(element_t *root)
{
    GList *childs = root->elements;

    g_hash_table_destroy(root->attrs);
    g_hash_table_destroy(root->namespaces);

    while(childs)
    {
        element_t *child = childs->data;

        element_t_tree_free(child);
        childs = childs->next;
    }
    g_list_free(root->elements);
}

/*Function recognize attribute names if they looks like ns:attr_name or xmlns:ns*/
/*TODO ns:attr*/
static gboolean
attr_find_pred(gpointer key, gpointer value _U_, gpointer user_data)
{
    gchar *attr_name = (gchar*) user_data;

    if( strcmp(attr_name, "xmlns") == 0 )
    {
        gchar *first_occur = epan_strcasestr(key, "xmlns:");
        if(first_occur && first_occur == key)
            return TRUE;
        else
            return FALSE;
    }
    return FALSE;
}

/*Functions returns element's attibute by name*/
attr_t*
get_attr(element_t *element, const gchar* attr_name)
{
    attr_t *result = g_hash_table_lookup(element->attrs, attr_name);
    
    if(!result)
    {
        result = g_hash_table_find(element->attrs, attr_find_pred, (gpointer)attr_name);
    }

    return result;
}

/*Functions returns element's attibute by name and namespace abbrev*/
attr_t*
get_attr_ext(element_t *element, const gchar* attr_name, const gchar* ns_abbrev)
{
    gchar* search_phrase;
    attr_t *result;

    if(strcmp(ns_abbrev,"")==0)
        search_phrase = ep_strdup(attr_name);
    else if(strcmp(attr_name, "xmlns") == 0)
        search_phrase = ep_strdup_printf("%s:%s",attr_name, ns_abbrev);
    else
        search_phrase = ep_strdup_printf("%s:%s", ns_abbrev, attr_name);
    
    result = g_hash_table_lookup(element->attrs, search_phrase);

    if(!result)
    {
        result = g_hash_table_find(element->attrs, attr_find_pred, (gpointer)attr_name);
    }

    return result;
}



gchar*
element_to_string(tvbuff_t *tvb, element_t *element)
{
    gchar *buff = NULL;
    
    if(tvb_offset_exists(tvb, element->offset+element->length-1))
    {
        buff = tvb_get_ephemeral_string(tvb, element->offset, element->length);
    }
    return buff;
}

gchar*
attr_to_string(tvbuff_t *tvb, attr_t *attr)
{
    gchar *buff = NULL;

    if(tvb_offset_exists(tvb, attr->offset + attr->length-1))
    {
        buff = tvb_get_ephemeral_string(tvb, attr->offset, attr->length);
    }
    return buff;
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

void
proto_tree_hide_first_child(proto_tree *tree)
{
    int i = 0;
    proto_tree_children_foreach(tree, children_foreach_hide_func, &i);
}

void
proto_tree_show_first_child(proto_tree *tree)
{
    int i = 0;
    proto_tree_children_foreach(tree, children_foreach_show_func, &i);
}

gchar*
proto_item_get_text(proto_item *item)
{
    field_info *fi = NULL;
    gchar *result;
    
    if(item == NULL)
        return NULL;

    fi = PITEM_FINFO(item);

    if(fi==NULL)
        return NULL;

    if (fi->rep == NULL)
        return NULL;
    

    result = ep_strdup(fi->rep->representation);
    return result;
}


void
display_attrs(proto_tree *tree, element_t *element, packet_info *pinfo, tvbuff_t *tvb, attr_info *attrs, guint n)
{
    proto_item *item = proto_tree_get_parent(tree);
    attr_t *attr;
    guint i;
    gboolean short_list_started = FALSE;
    GList *attrs_copy = g_hash_table_get_values(element->attrs);
    GList *attrs_copy_head;

    if(element->default_ns_abbrev)
        proto_item_append_text(item, "(%s)",element->default_ns_abbrev);

    proto_item_append_text(item," [");
    for(i = 0; i < n && attrs!=NULL; i++)
    {
        attr = get_attr(element, attrs[i].name);
        if(attr)
        {
            if(attrs[i].hf != -1)
            {
                if(attr->name)
                    proto_tree_add_string_format(tree, attrs[i].hf, tvb, attr->offset, attr->length, attr->value,"%s: %s", attr->name, attr->value);
                else
                    proto_tree_add_string(tree, attrs[i].hf, tvb, attr->offset, attr->length, attr->value);
            }
            else
            {
                proto_tree_add_text(tree, tvb, attr->offset, attr->length, "%s: %s", attr->name?attr->name:attrs[i].name, attr->value);
            }

            if(attrs[i].in_short_list)
            {
                if(short_list_started)
                {
                    proto_item_append_text(item," ");
                }
                proto_item_append_text(item,"%s=\"%s\"",attr->name?attr->name:attrs[i].name, attr->value);
                short_list_started = TRUE;
            }

            attrs_copy = g_list_remove(attrs_copy, attr);

        } else if(attrs[i].is_required)
        {
            expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
                    "Required attribute \"%s\" doesn't appear in \"%s\".",attrs[i].name,
                    element->name);
        }

        if(attrs[i].val_func)
        {
            if(attr)
                attrs[i].val_func(pinfo, item, attrs[i].name, attr->value, attrs[i].data);
            else
                attrs[i].val_func(pinfo, item, attrs[i].name, NULL, attrs[i].data);
        }
    }
    proto_item_append_text(item,"]");

    attrs_copy_head = attrs_copy;

    /*displays attributes that weren't recognized*/
    while(attrs_copy)
    {
        attr_t *unknown_attr = attrs_copy->data;
        proto_item* unknown_attr_item;
        unknown_attr_item = proto_tree_add_string_format(tree,
                hf_xmpp_unknown_attr, tvb, unknown_attr->offset, unknown_attr->length,
                unknown_attr->name, "%s: %s", unknown_attr->name, unknown_attr->value);
        #ifdef XMPP_DEBUG
        proto_item_append_text(unknown_attr_item, " [UNKNOWN ATTR]");
        expert_add_info_format(pinfo, unknown_attr_item, PI_UNDECODED, PI_NOTE,"Unknown attribute %s.", unknown_attr->name);
        #endif
        attrs_copy = attrs_copy->next;
    }
    g_list_free(attrs_copy_head);
}

void
display_attrs_ext(proto_tree *tree, element_t *element, packet_info *pinfo, tvbuff_t *tvb, attr_info_ext *attrs, guint n)
{
    proto_item *item = proto_tree_get_parent(tree);
    attr_t *attr;
    guint i;
    gboolean short_list_started = FALSE;
    GList *attrs_copy = g_hash_table_get_values(element->attrs);
    GList *attrs_copy_head;

    GList *ns_abbrevs_head, *ns_abbrevs = g_hash_table_get_keys(element->namespaces);
    GList *ns_fullnames_head, *ns_fullnames = g_hash_table_get_values(element->namespaces);
    ns_abbrevs_head = ns_abbrevs;
    ns_fullnames_head = ns_fullnames;

    if(element->default_ns_abbrev)
        proto_item_append_text(item, "(%s)",element->default_ns_abbrev);

    proto_item_append_text(item," [");
    while(ns_abbrevs && ns_fullnames)
    {
        for (i = 0; i < n && attrs != NULL; i++) {
            if(strcmp(ns_fullnames->data, attrs[i].ns) == 0)
            {
                attr = get_attr_ext(element, attrs[i].info.name, ns_abbrevs->data);
                if(!attr && element->default_ns_abbrev && strcmp(ns_abbrevs->data, element->default_ns_abbrev)==0)
                    attr = get_attr_ext(element, attrs[i].info.name, "");

                if (attr) {
                    if (attrs[i].info.hf != -1) {
                        if (attr->name)
                            proto_tree_add_string_format(tree, attrs[i].info.hf, tvb, attr->offset, attr->length, attr->value, "%s: %s", attr->name, attr->value);
                        else
                            proto_tree_add_string(tree, attrs[i].info.hf, tvb, attr->offset, attr->length, attr->value);
                    } else {
                        proto_tree_add_text(tree, tvb, attr->offset, attr->length, "%s: %s", attr->name ? attr->name : attrs[i].info.name, attr->value);
                    }

                    if (attrs[i].info.in_short_list) {
                        if (short_list_started) {
                            proto_item_append_text(item, " ");
                        }
                        proto_item_append_text(item, "%s=\"%s\"", attr->name ? attr->name : attrs[i].info.name, attr->value);
                        short_list_started = TRUE;
                    }

                    attrs_copy = g_list_remove(attrs_copy, attr);

                } else if (attrs[i].info.is_required) {
                    expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
                            "Required attribute \"%s\" doesn't appear in \"%s\".", attrs[i].info.name,
                            element->name);
                }

                if (attrs[i].info.val_func) {
                    if (attr)
                        attrs[i].info.val_func(pinfo, item, attrs[i].info.name, attr->value, attrs[i].info.data);
                    else
                        attrs[i].info.val_func(pinfo, item, attrs[i].info.name, NULL, attrs[i].info.data);
                }
            }
        }
        ns_abbrevs = ns_abbrevs->next;
        ns_fullnames = ns_fullnames->next;
    }
    proto_item_append_text(item,"]");

    attrs_copy_head = attrs_copy;

    /*displays attributes that weren't recognized*/
    while(attrs_copy)
    {
        attr_t *unknown_attr = attrs_copy->data;
        proto_item *unknown_attr_item;

        //printf("%s %s\n",element->default_ns_abbrev,unknown_attr->name);

        unknown_attr_item = proto_tree_add_string_format(tree,
                hf_xmpp_unknown_attr, tvb, unknown_attr->offset, unknown_attr->length,
                unknown_attr->name, "%s: %s", unknown_attr->name, unknown_attr->value);
       #ifdef XMPP_DEBUG
        proto_item_append_text(unknown_attr_item, " [UNKNOWN ATTR]");
        expert_add_info_format(pinfo, unknown_attr_item, PI_UNDECODED, PI_NOTE,"Unknown attribute %s. [DISP ATTR EXT]", unknown_attr->name);
        #endif

        attrs_copy = attrs_copy->next;
    }
    g_list_free(attrs_copy_head);
    g_list_free(ns_abbrevs_head);
    g_list_free(ns_fullnames_head);
}

struct name_attr_t
{
    gchar *name;
    gchar *attr_name;
    gchar *attr_value;
};

/*
returns pointer to the struct that contains 3 strings(element name, attribute name, attribute value)
*/
gpointer
name_attr_struct(gchar *name, gchar *attr_name, gchar *attr_value)
{
    struct name_attr_t *result;

    result = ep_alloc(sizeof(struct name_attr_t));
    result->name = name;
    result->attr_name = attr_name;
    result->attr_value = attr_value;
    return result;
}

void
display_elems(proto_tree *tree, element_t *parent, packet_info *pinfo, tvbuff_t *tvb, elem_info *elems, guint n)
{
    guint i;

    for(i = 0; i < n && elems!=NULL; i++)
    {
        element_t *elem = NULL;

        if(elems[i].type == NAME_AND_ATTR)
        {
            gboolean loop = TRUE;

            struct
            {
                gchar *name;
                gchar *attr_name;
                gchar *attr_value;
            } *a;

            a = elems[i].data;

            while(loop && (elem = steal_element_by_name_and_attr(parent, a->name, a->attr_name, a->attr_value))!=NULL)
            {
                elems[i].elem_func(tree, tvb, pinfo, elem);
                if(elems[i].occurrence == ONE)
                    loop = FALSE;
            }
        } else if(elems[i].type == NAME)
        {
            gboolean loop = TRUE;
            gchar *name = elems[i].data;

            while(loop && (elem = steal_element_by_name(parent, name))!=NULL)
            {
                elems[i].elem_func(tree, tvb, pinfo, elem);
                if(elems[i].occurrence == ONE)
                    loop = FALSE;
            }
        }
        else if(elems[i].type == ATTR)
        {
            gboolean loop = TRUE;
            struct {
                gchar *name;
                gchar *attr_name;
                gchar *attr_value;
            } *attr = elems[i].data;
            
            while(loop && (elem = steal_element_by_attr(parent, attr->attr_name, attr->attr_value))!=NULL)
            {
                elems[i].elem_func(tree, tvb, pinfo, elem);
                if(elems[i].occurrence == ONE)
                    loop = FALSE;
            }

        } else if(elems[i].type == NAMES)
        {
            gboolean loop = TRUE;
            array_t *names = elems[i].data;

            while(loop && (elem =  steal_element_by_names(parent, (const gchar**)names->data, names->length))!=NULL)
            {
                elems[i].elem_func(tree, tvb, pinfo, elem);
                if(elems[i].occurrence == ONE)
                    loop = FALSE;
            }
        }           
    }

    xmpp_unknown(tree, tvb, pinfo, parent);
}

/*
function checks that variable value is in array ((array_t)data)->data
*/
void
val_enum_list(packet_info *pinfo, proto_item *item, gchar *name, gchar *value, gpointer data)
{
    array_t *enums_array = data;

    gint i;
    gboolean value_in_enums = FALSE;

    gchar **enums =  (char**)enums_array->data;

    if (value != NULL) {
        for (i = 0; i < enums_array->length; i++) {
            if (strcmp(value, enums[i]) == 0) {
                value_in_enums = TRUE;
                break;
            }
        }
        if (!value_in_enums) {
            expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
                    "Field \"%s\" has unexpected value \"%s\"",
                    name, value);
        }
    }
}


void
change_elem_to_attrib(const gchar *elem_name, const gchar *attr_name, element_t *parent, attr_t* (*transform_func)(element_t *element))
{
    element_t *element = NULL;
    attr_t *fake_attr = NULL;

    element = steal_element_by_name(parent, elem_name);
    if(element)
        fake_attr = transform_func(element);

    if(fake_attr)
        g_hash_table_insert(parent->attrs, (gpointer)attr_name, fake_attr);
}

attr_t*
transform_func_cdata(element_t *elem)
{
    attr_t *result = ep_init_attr_t(elem->data?elem->data->value:"", elem->offset, elem->length);
    return result;
}

static void
copy_hash_table_func(gpointer key, gpointer value, gpointer user_data)
{
    GHashTable *dst = user_data;
    g_hash_table_insert(dst, key, value);
}

void copy_hash_table(GHashTable *src, GHashTable *dst)
{
    g_hash_table_foreach(src, copy_hash_table_func, dst);
}

/*
static void
printf_hash_table_func(gpointer key, gpointer value, gpointer user_data _U_)
{
    printf("'%s' '%s'\n", (gchar*)key, (gchar*)value);
}

void
printf_elements(element_t *root)
{
    GList *elems = root->elements;

    printf("%s\n", root->name);
    g_hash_table_foreach(root->namespaces, printf_hash_table_func, NULL);
    while(elems)
    {
        printf_elements(elems->data);
        elems = elems->next;
    }
}*/