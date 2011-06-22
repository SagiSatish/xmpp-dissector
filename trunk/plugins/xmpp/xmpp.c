#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/proto.h>
#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/expert.h>

#include <epan/dissectors/packet-xml.h>

#include <plugins/xmpp/xmpp.h>

array_t*
ep_init_array_t(const gchar** array, gint len)
{
    array_t *result;

    result = ep_alloc(sizeof(array_t));
    result->data = array;
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

    return result;
}

gint
element_t_cmp(gconstpointer a, gconstpointer b)
{
    return strcmp(((element_t*)a)->name,((element_t*)b)->name);
}

GList*
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
element_t*
steal_element_by_name(element_t *packet,const gchar *name)
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
get_first_element(element_t *packet)
{
    if(packet->elements && packet->elements->data)
        return packet->elements->data;
    else
        return NULL;
}

//Function converts xml_frame_t structure to element_t (simpler representation)
element_t*
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


gchar*
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

/*
static void
element_tree_delete()
{
    //TODO
}
*/


void
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
void
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