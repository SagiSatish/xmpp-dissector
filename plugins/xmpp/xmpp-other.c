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
#include <plugins/xmpp/xmpp-jingle.h>
#include <plugins/xmpp/xmpp-other.h>

static void xmpp_disco_items_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element);

static void xmpp_roster_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element);

static void xmpp_disco_info_identity(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element);
static void xmpp_disco_info_feature(proto_tree *tree, tvbuff_t *tvb, element_t *element);

static void xmpp_bytestreams_streamhost(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_bytestreams_streamhost_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_bytestreams_activate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_bytestreams_udpsuccess(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_si_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_si_file_range(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

static void xmpp_x_data_field(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_x_data_field_option(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_x_data_field_value(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

static void xmpp_muc_history(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_muc_user_item(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_muc_user_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_muc_user_invite(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_hashes_hash(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_jitsi_inputevt_rmt_ctrl(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void
xmpp_iq_bind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *bind_item;
    proto_tree *bind_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"resource", hf_xmpp_iq_bind_resource, FALSE, TRUE, NULL, NULL},
        {"jid", hf_xmpp_iq_bind_jid, FALSE, TRUE, NULL, NULL}
    };

    bind_item = proto_tree_add_item(tree, hf_xmpp_iq_bind, tvb, element->offset, element->length, FALSE);
    bind_tree = proto_item_add_subtree(bind_item, ett_xmpp_iq_bind);

    change_elem_to_attrib("resource", "resource", element, transform_func_cdata);
    change_elem_to_attrib("jid", "jid", element, transform_func_cdata);

    display_attrs(bind_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(bind_tree, tvb, pinfo, element);
}

void
xmpp_session(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    attr_t *xmlns  = get_attr(element, "xmlns");

    col_append_fstr(pinfo->cinfo, COL_INFO, "SESSION ");

    proto_tree_add_string_format(tree, hf_xmpp_iq_session, tvb, element->offset, element->length, xmlns?xmlns->value:"","SESSION (%s)",xmlns?xmlns->value:"");
}

void
xmpp_vcard(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *vcard_item;
    proto_tree *vcard_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"value", -1, FALSE, FALSE, NULL, NULL}
    };

    element_t *cdata;

    col_append_fstr(pinfo->cinfo, COL_INFO, "VCARD ");

    vcard_item = proto_tree_add_item(tree, hf_xmpp_vcard, tvb, element->offset, element->length, FALSE);\
    vcard_tree = proto_item_add_subtree(vcard_item, ett_xmpp_vcard);

    cdata = get_first_element(element);

    if(cdata)
    {
        attr_t *fake_cdata = ep_init_attr_t(element_to_string(tvb, cdata), cdata->offset, cdata->length);
        g_hash_table_insert(element->attrs,"value", fake_cdata);
    }
    display_attrs(vcard_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

}

void
xmpp_vcard_x_update(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"photo", -1, FALSE, FALSE, NULL, NULL}
    };

    element_t *photo;

    x_item = proto_tree_add_item(tree, hf_xmpp_vcard_x_update, tvb, element->offset, element->length, FALSE);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_vcard_x_update);

    if((photo = steal_element_by_name(element, "photo"))!=NULL)
    {
        attr_t *fake_photo = ep_init_attr_t(photo->data?photo->data->value:"", photo->offset, photo->length);
        g_hash_table_insert(element->attrs, "photo", fake_photo);
    }

    display_attrs(x_tree, element,pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

void
xmpp_disco_items_query(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"node", hf_xmpp_query_node, FALSE, TRUE, NULL, NULL}
    };

    element_t *item;

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(disco#items) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((item = steal_element_by_name(element, "item")) != NULL)
    {
        xmpp_disco_items_item(query_tree, tvb, pinfo, item);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_disco_items_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    attr_info attrs_info[] = {
        {"jid", hf_xmpp_query_item_jid, TRUE, TRUE, NULL, NULL},
        {"name", hf_xmpp_query_item_name, FALSE, TRUE, NULL, NULL},
        {"node", hf_xmpp_query_item_node, FALSE, TRUE, NULL, NULL}
    };

    item_item = proto_tree_add_item(tree, hf_xmpp_query_item, tvb, element->offset, element->length, FALSE);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_query_item);

    display_attrs(item_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(item_tree, tvb, pinfo, element);
}

void
xmpp_roster_query(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"ver", -1, FALSE, TRUE, NULL, NULL},
    };

    element_t *item;

     col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(jabber:iq:roster) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while ((item = steal_element_by_name(element, "item")) != NULL) {
        xmpp_roster_item(query_tree, tvb, pinfo, item);
    }
    
    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_roster_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    const gchar *ask_enums[] = {"subscribe"};
    const gchar *subscription_enums[] = {"both","from","none","remove","to"};

    array_t *ask_enums_array = ep_init_array_t(ask_enums,array_length(ask_enums));
    array_t *subscription_array = ep_init_array_t(subscription_enums,array_length(subscription_enums));

    attr_info attrs_info[] = {
        {"jid", hf_xmpp_query_item_jid, TRUE, TRUE, NULL, NULL},
        {"name", hf_xmpp_query_item_name, FALSE, TRUE, NULL, NULL},
        {"ask", hf_xmpp_query_item_ask, FALSE, TRUE, val_enum_list, ask_enums_array},
        {"approved", hf_xmpp_query_item_approved, FALSE, TRUE, NULL, NULL},
        {"subscription", hf_xmpp_query_item_subscription, FALSE, TRUE, val_enum_list, subscription_array},
    };

    element_t *group;

    item_item = proto_tree_add_item(tree, hf_xmpp_query_item, tvb, element->offset, element->length, FALSE);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_query_item);

    display_attrs(item_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((group = steal_element_by_name(element,"group"))!=NULL)
    {
        proto_tree_add_string(item_tree, hf_xmpp_query_item_group, tvb, group->offset, group->length, elem_cdata(group));
    }

    xmpp_unknown(item_tree, tvb, pinfo, element);
}

void
xmpp_disco_info_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"node", hf_xmpp_query_node, FALSE, TRUE, NULL, NULL}
    };

    element_t *identity, *feature, *x_data;

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(disco#info) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));


    while((identity = steal_element_by_name(element, "identity")) != NULL)
    {
        xmpp_disco_info_identity(query_tree, tvb, pinfo, identity);
    }

    while((feature = steal_element_by_name(element, "feature")) != NULL)
    {
        xmpp_disco_info_feature(query_tree, tvb, feature);
    }

    if((x_data = steal_element_by_name_and_attr(element, "x", "xmlns", "jabber:x:data")) != NULL)
    {
        xmpp_x_data(query_tree, tvb, pinfo, x_data);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_disco_info_identity(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *identity_item;
    proto_tree *identity_tree;

    attr_info attrs_info[] = {
        {"category", hf_xmpp_query_identity_category, TRUE, TRUE, NULL, NULL},
        {"name", hf_xmpp_query_identity_name, FALSE, TRUE, NULL, NULL},
        {"type", hf_xmpp_query_identity_type, TRUE, TRUE, NULL, NULL}
    };

    identity_item = proto_tree_add_item(tree, hf_xmpp_query_identity, tvb, element->offset, element->length, FALSE);
    identity_tree = proto_item_add_subtree(identity_item, ett_xmpp_query_identity);

    display_attrs(identity_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(identity_tree, tvb, pinfo, element);

}

static void
xmpp_disco_info_feature(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{

    attr_t *var = get_attr(element, "var");

    if(var)
    {
        proto_tree_add_string_format(tree, hf_xmpp_query_feature, tvb, var->offset, var->length, var->value, "FEATURE [%s]", var->value);
    }
}

void
xmpp_bytestreams_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    const gchar *mode_enums[] = {"tcp", "udp"};
    array_t *mode_array = ep_init_array_t(mode_enums, array_length(mode_enums));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"sid", -1, FALSE, TRUE, NULL, NULL},
        {"mode", -1, FALSE, TRUE, val_enum_list, mode_array},
        {"dstaddr", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *streamhost, *streamhost_used, *activate, *udpsuccess;

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(bytestreams) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));


    while((streamhost = steal_element_by_name(element, "streamhost")) != NULL)
    {
        xmpp_bytestreams_streamhost(query_tree, tvb, pinfo, streamhost);
    }

    if((streamhost_used = steal_element_by_name(element, "streamhost-used")) != NULL)
    {
        xmpp_bytestreams_streamhost_used(query_tree, tvb, pinfo, streamhost_used);
    }

    if((activate = steal_element_by_name(element, "activate")) != NULL)
    {
        xmpp_bytestreams_activate(query_tree, tvb, pinfo, activate);
    }

    if((udpsuccess = steal_element_by_name(element, "udpsuccess")) != NULL)
    {
        xmpp_bytestreams_udpsuccess(query_tree, tvb, pinfo, udpsuccess);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_streamhost(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *sh_item;
    proto_tree *sh_tree;

    attr_info attrs_info[] = {
        {"jid", -1, TRUE, TRUE, NULL, NULL},
        {"host", -1, TRUE, TRUE, NULL, NULL},
        {"port", -1, FALSE, TRUE, NULL, NULL}
    };

    sh_item = proto_tree_add_item(tree, hf_xmpp_query_streamhost, tvb, element->offset, element->length, FALSE);
    sh_tree = proto_item_add_subtree(sh_item, ett_xmpp_query_streamhost);

    display_attrs(sh_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(sh_tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_streamhost_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *shu_item;
    proto_tree *shu_tree;

    attr_info attrs_info[] = {
        {"jid", -1, TRUE, TRUE, NULL, NULL}
    };

    shu_item = proto_tree_add_item(tree, hf_xmpp_query_streamhost_used, tvb, element->offset, element->length, FALSE);
    shu_tree = proto_item_add_subtree(shu_item, ett_xmpp_query_streamhost_used);

    display_attrs(shu_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(shu_tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_activate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_tree_add_string(tree, hf_xmpp_query_activate, tvb, element->offset, element->length, elem_cdata(element));
    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_udpsuccess(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *udps_item;
    proto_tree *udps_tree;

    attr_info attrs_info[] = {
        {"dstaddr", -1, TRUE, TRUE, NULL, NULL}
    };

    udps_item = proto_tree_add_item(tree, hf_xmpp_query_udpsuccess, tvb, element->offset, element->length, FALSE);
    udps_tree =proto_item_add_subtree(udps_item, ett_xmpp_query_udpsuccess);

    display_attrs(udps_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(udps_tree, tvb, pinfo, element);
}



/*SI File Transfer*/
void
xmpp_si(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *si_item;
    proto_tree *si_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"id", -1, FALSE, FALSE, NULL, NULL},
        {"mime-type", -1, FALSE, TRUE, NULL, NULL},
        {"profile", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *file, *feature_neg;

    col_append_fstr(pinfo->cinfo, COL_INFO, "SI ");

    si_item = proto_tree_add_item(tree, hf_xmpp_si, tvb, element->offset, element->length, FALSE);
    si_tree = proto_item_add_subtree(si_item, ett_xmpp_si);

    display_attrs(si_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((file = steal_element_by_name(element, "file"))!=NULL)
    {
        xmpp_si_file(si_tree, tvb, pinfo, file);
    }

    while((feature_neg = steal_element_by_name(element, "feature"))!=NULL)
    {
        xmpp_feature_neg(si_tree, tvb, pinfo, feature_neg);
    }



    xmpp_unknown(si_tree, tvb, pinfo, element);
}

static void
xmpp_si_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *file_item;
    proto_tree *file_tree;

    attr_info attrs_info[]  ={
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"name", -1, TRUE, TRUE, NULL, NULL},
        {"size", -1, TRUE, TRUE, NULL, NULL},
        {"date", -1, FALSE, FALSE, NULL, NULL},
        {"hash", -1, FALSE, FALSE, NULL, NULL},
        {"desc", -1, FALSE, FALSE, NULL, NULL}
    };

    element_t *desc, *range;

    file_item = proto_tree_add_item(tree, hf_xmpp_si_file, tvb, element->offset, element->length, FALSE);
    file_tree = proto_item_add_subtree(file_item, ett_xmpp_si_file);

    if((desc = steal_element_by_name(element, "desc"))!=NULL)
    {
         attr_t *fake_desc = ep_init_attr_t(desc->data?desc->data->value:"", desc->offset, desc->length);
         g_hash_table_insert(element->attrs, "desc", fake_desc);
    }

    if((range = steal_element_by_name(element, "range"))!=NULL)
    {
        xmpp_si_file_range(file_tree, tvb, pinfo, range);
    }

    display_attrs(file_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(file_tree, tvb, pinfo, element);
}

static void
xmpp_si_file_range(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *range_item;
    proto_tree *range_tree;

    attr_info attrs_info[] = {
        {"offset", -1, FALSE, TRUE, NULL, NULL},
        {"length", -1, FALSE, TRUE, NULL, NULL}
    };

    range_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "RANGE: ");
    range_tree = proto_item_add_subtree(range_item, ett_xmpp_si_file_range);

    display_attrs(range_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(range_tree, tvb, pinfo, element);

}

/*Feature Negotiation*/
void
xmpp_feature_neg(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *feature_item;
    proto_tree *feature_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    element_t *x_data;

    feature_item = proto_tree_add_item(tree, hf_xmpp_iq_feature_neg, tvb, element->offset, element->length, FALSE);
    feature_tree = proto_item_add_subtree(feature_item, ett_xmpp_iq_feature_neg);

    display_attrs(feature_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((x_data = steal_element_by_name_and_attr(element, "x", "xmlns", "jabber:x:data"))!=NULL)
    {
        xmpp_x_data(feature_tree, tvb, pinfo, x_data);
    }

    xmpp_unknown(feature_tree, tvb, pinfo, element);
}


/*jabber:x:data*/
void
xmpp_x_data(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    const gchar *type_enums[] = {"cancel", "form", "result", "submit"};
    array_t *type_array = ep_init_array_t(type_enums, array_length(type_enums));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"type", -1, TRUE, TRUE, val_enum_list, type_array},
        {"title", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *field, *title; /*TODO instructions, title, reported, item*/

    x_item = proto_tree_add_item(tree, hf_xmpp_x_data, tvb, element->offset, element->length, FALSE);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_x_data);

    if((title = steal_element_by_name(element, "title"))!=NULL)
    {
        attr_t *fake_title = ep_init_attr_t(title->data?title->data->value:"", title->offset, title->length);
        g_hash_table_insert(element->attrs, "title", fake_title);
    }

    display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((field = steal_element_by_name(element, "field"))!=NULL)
    {
        xmpp_x_data_field(x_tree, tvb, pinfo, field);
    }

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

static void
xmpp_x_data_field(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *field_item;
    proto_tree *field_tree;

    const gchar *type_enums[] = {"boolean", "fixed", "hidden", "jid-multi",
        "jid-single", "list-multi", "list-single", "text-multi", "text-single",
        "text-private"
    };
    array_t *type_array = ep_init_array_t(type_enums, array_length(type_enums));

    attr_info attrs_info[] =
    {
        {"label", -1, FALSE, TRUE, NULL, NULL},
        {"type", -1, FALSE, TRUE, val_enum_list, type_array},
        {"var", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t /**desc, *required,*/ *value, *option;

    field_item = proto_tree_add_item(tree, hf_xmpp_x_data_field, tvb, element->offset, element->length, FALSE);
    field_tree = proto_item_add_subtree(field_item, ett_xmpp_x_data_field);

    display_attrs(field_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((option = steal_element_by_name(element, "option"))!=NULL)
    {
        xmpp_x_data_field_option(field_tree, tvb, pinfo, option);
    }

    while((value = steal_element_by_name(element, "value"))!=NULL)
    {
        xmpp_x_data_field_value(field_tree, tvb, pinfo, value);
    }

    xmpp_unknown(field_item, tvb, pinfo, element);

}

static void
xmpp_x_data_field_option(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *option_item;
    proto_tree *option_tree;

    attr_info attrs_info[] = {
        {"label", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *value;

    option_item = proto_tree_add_item(tree, hf_xmpp_x_data_field_value, tvb, element->offset, element->length, FALSE);
    option_tree = proto_item_add_subtree(option_item, ett_xmpp_x_data_field_value);

    if((value = steal_element_by_name(element, "value"))!=NULL)
    {
        attr_t *fake_value = ep_init_attr_t(value->data?value->data->value:"",value->offset, value->length);
        g_hash_table_insert(element->attrs, "value", fake_value);
    }

    display_attrs(option_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(option_tree, tvb, pinfo, element);
}

static void
xmpp_x_data_field_value(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *value_item;
    proto_tree *value_tree;

    attr_info attrs_info[] = {
        {"label", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };
    attr_t *fake_value;

    value_item = proto_tree_add_item(tree, hf_xmpp_x_data_field_value, tvb, element->offset, element->length, FALSE);
    value_tree = proto_item_add_subtree(value_item, ett_xmpp_x_data_field_value);



   fake_value = ep_init_attr_t(element->data?element->data->value:"",element->offset, element->length);
   g_hash_table_insert(element->attrs, "value", fake_value);


    display_attrs(value_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(value_tree, tvb, pinfo, element);
}


/*In-Band Bytestreams*/
void
xmpp_ibb_open(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *open_item;
    proto_tree *open_tree;

    const gchar *stanza_enums[] = {"iq","message"};
    array_t *stanza_array = ep_init_array_t(stanza_enums, array_length(stanza_enums));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"sid", -1, TRUE, TRUE, NULL, NULL},
        {"block-size", -1, TRUE, TRUE, NULL, NULL},
        {"stanza", -1, FALSE, TRUE, val_enum_list, stanza_array}
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "IBB-OPEN ");

    open_item = proto_tree_add_item(tree, hf_xmpp_ibb_open, tvb, element->offset, element->length, FALSE);
    open_tree = proto_item_add_subtree(open_item, ett_xmpp_ibb_open);

    display_attrs(open_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(open_tree, tvb, pinfo, element);
}

void
xmpp_ibb_close(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *close_item;
    proto_tree *close_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"sid", -1, TRUE, TRUE, NULL, NULL}
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "IBB-CLOSE ");

    close_item = proto_tree_add_item(tree, hf_xmpp_ibb_close, tvb, element->offset, element->length, FALSE);
    close_tree = proto_item_add_subtree(close_item, ett_xmpp_ibb_close);

    display_attrs(close_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(close_tree, tvb, pinfo, element);
}

void
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

    col_append_fstr(pinfo->cinfo, COL_INFO, "IBB-DATA ");

    data_item = proto_tree_add_item(tree, hf_xmpp_ibb_data, tvb, element->offset, element->length, FALSE);
    data_tree = proto_item_add_subtree(data_item, ett_xmpp_ibb_data);

    if(element->data)
    {
        attr_t *fake_data = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_data);
    }

    display_attrs(data_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(data_tree, tvb, pinfo, element);
}


/*Delayed Delivery urn:xmpp:delay and jabber:x:delay*/
void
xmpp_delay(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *delay_item;
    proto_tree *delay_tree;

    attr_info attrs_info[]={
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"from", -1, FALSE, TRUE, NULL, NULL},
        {"stamp", -1, TRUE, TRUE, NULL, NULL},
        {"value", -1, FALSE, TRUE, NULL, NULL}
    };

    delay_item = proto_tree_add_item(tree, hf_xmpp_delay, tvb, element->offset, element->length, FALSE);
    delay_tree = proto_item_add_subtree(delay_item, ett_xmpp_delay);

    if(element->data)
    {
        attr_t *fake_value = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_value);
    }

    display_attrs(delay_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(delay_tree, tvb, pinfo, element);
}

/*Entity Capabilities http://jabber.org/protocol/caps*/
void
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

    display_attrs(caps_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(caps_tree, tvb, pinfo, element);
}

/*Message Events jabber:x:event*/
void
xmpp_x_event(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"condition", hf_xmpp_x_event_condition, TRUE, TRUE, NULL, NULL},
        {"id", -1, FALSE, TRUE, NULL, NULL}
    };
    
    const gchar *cond_names[] = {"offline", "delivered", "displayed", "composing"};

    attr_t *fake_cond;

    element_t *cond, *id;

    gchar *cond_value = ep_strdup("");

    x_item =  proto_tree_add_item(tree, hf_xmpp_x_event, tvb, element->offset, element->length, FALSE);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_x_event);

    if((id = steal_element_by_name(element, "id"))!=NULL)
    {
        attr_t *fake_id = ep_init_attr_t(id->data?id->data->value:"", id->offset, id->length);
        g_hash_table_insert(element->attrs, "id", fake_id);
    }

    while((cond = steal_element_by_names(element, cond_names, array_length(cond_names))) != NULL)
    {
        if(strcmp(cond_value,"") != 0)
            cond_value = ep_strdup_printf("%s/%s",cond_value, cond->name);
        else
            cond_value = ep_strdup(cond->name);
    }

    fake_cond = ep_init_attr_t(cond_value, element->offset, element->length);
    g_hash_table_insert(element->attrs, "condition", fake_cond);
    

    display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

/*Multi-User Chat http://jabber.org/protocol/muc*/
void
xmpp_muc_x(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    attr_info attrs_info [] ={
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"password", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *pass, *hist;

    x_item = proto_tree_add_item(tree, hf_xmpp_muc_x, tvb, element->offset, element->length, FALSE);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_muc_x);

    if((pass = steal_element_by_name(element, "password"))!=NULL)
    {
        attr_t *fake_pass = ep_init_attr_t(pass->data?pass->data->value:"",pass->offset, pass->length);
        g_hash_table_insert(element->attrs, "password", fake_pass);
    }

    display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    if((hist = steal_element_by_name(element, "history"))!=NULL)
    {
        xmpp_muc_history(x_tree, tvb, pinfo, hist);
    }

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

static void
xmpp_muc_history(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *hist_item;
    proto_tree *hist_tree;

    attr_info attrs_info[] = {
        {"maxchars", -1, FALSE, TRUE, NULL, NULL},
        {"maxstanzas", -1, FALSE, TRUE, NULL, NULL},
        {"seconds", -1, FALSE, TRUE, NULL, NULL},
        {"since", -1, FALSE, TRUE, NULL, NULL}
    };

    hist_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "HISTORY: ");
    hist_tree = proto_item_add_subtree(hist_item, ett_xmpp_muc_hist);

    display_attrs(hist_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(hist_tree, tvb, pinfo, element);
}

/*Multi-User Chat http://jabber.org/protocol/muc#user*/
void
xmpp_muc_user_x(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *x_item;
    proto_tree *x_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"password", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *item, *status, *invite, *password;
    /*TODO decline destroy*/

    x_item = proto_tree_add_item(tree, hf_xmpp_muc_user_x, tvb, element->offset, element->length, FALSE);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_muc_user_x);

    if((password = steal_element_by_name(element, "password"))!=NULL)
    {
        attr_t *fake_pass = ep_init_attr_t(password->data?password->data->value:"",password->offset, password->length);
        g_hash_table_insert(element->attrs, "password", fake_pass);
    }

    display_attrs(x_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((item = steal_element_by_name(element, "item"))!=NULL)
    {
        xmpp_muc_user_item(x_tree, tvb, pinfo, item);
    }

    while((status = steal_element_by_name(element, "status"))!=NULL)
    {
        xmpp_muc_user_status(x_tree, tvb, pinfo, status);
    }

    while((invite = steal_element_by_name(element, "invite"))!=NULL)
    {
        xmpp_muc_user_invite(x_tree, tvb, pinfo, invite);
    }

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

static void
xmpp_muc_user_item(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    const gchar *affiliation_enums[] = {"admin", "member", "none", "outcast", "owner"};
    array_t  *affil_array = ep_init_array_t(affiliation_enums, array_length(affiliation_enums));

    const gchar *role_enums[] = {"none", "moderator", "participant", "visitor"};
    array_t *role_array = ep_init_array_t(role_enums, array_length(role_enums));

    attr_info attrs_info [] ={
        {"affiliation", -1, FALSE, TRUE, val_enum_list, affil_array},
        {"jid", -1, FALSE, TRUE, NULL, NULL},
        {"nick", -1, FALSE, TRUE, NULL, NULL},
        {"role", -1, FALSE, TRUE, val_enum_list, role_array},
        {"reason", -1, FALSE, TRUE, NULL, NULL},
        {"actor_jid", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *reason, *actor;
    /*TODO continue - it's not clear to me, in schema it's marked as empty, but in examples it has CDATA*/

    item_item = proto_tree_add_item(tree, hf_xmpp_muc_user_item, tvb, element->offset, element->length, FALSE);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_muc_user_item);

    if((reason = steal_element_by_name(element, "reason"))!=NULL)
    {
        attr_t *fake_reason = ep_init_attr_t(reason->data?reason->data->value:"",reason->offset, reason->length);
        g_hash_table_insert(element->attrs,"reason",fake_reason);
    }

    if((actor = steal_element_by_name(element, "actor"))!=NULL)
    {
        attr_t *jid = get_attr(actor, "jid");
        attr_t *fake_actor_jid = ep_init_attr_t(jid?jid->value:"",actor->offset, actor->length);
        g_hash_table_insert(element->attrs, "actor_jid", fake_actor_jid);
    }

    display_attrs(item_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(item_tree, tvb, pinfo, element);
}

static void
xmpp_muc_user_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    attr_t *code = get_attr(element, "code");
    proto_tree_add_text(tree, tvb, element->offset, element->length, "STATUS [code=\"%s\"]",code?code->value:"");

    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_muc_user_invite(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *invite_item;
    proto_tree *invite_tree;

    attr_info attrs_info[] = {
        {"from", -1, FALSE, TRUE, NULL, NULL},
        {"to", -1, FALSE, TRUE, NULL, NULL},
        {"reason", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *reason;

    invite_item = proto_tree_add_item(tree, hf_xmpp_muc_user_invite, tvb, element->offset, element->length, FALSE);
    invite_tree = proto_item_add_subtree(invite_item, ett_xmpp_muc_user_invite);

    if((reason = steal_element_by_name(element, "reason"))!=NULL)
    {
        attr_t *fake_reason = ep_init_attr_t(reason->data?reason->data->value:"",reason->offset, reason->length);
        g_hash_table_insert(element->attrs, "reason", fake_reason);
    }

    display_attrs(invite_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(invite_tree, tvb, pinfo, element);
}

/*Multi-User Chat http://jabber.org/protocol/muc#owner*/
void
xmpp_muc_owner_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    element_t *x_data;
    /*TODO destroy*/

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(muc#owner) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    if((x_data = steal_element_by_name_and_attr(element, "x", "xmlns", "jabber:x:data"))!=NULL)
    {
        xmpp_x_data(query_tree, tvb, pinfo, x_data);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);

}

/*Multi-User Chat http://jabber.org/protocol/muc#admin*/
void
xmpp_muc_admin_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    element_t *item;

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(muc#admin) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((item = steal_element_by_name(element, "item"))!=NULL)
    {
        /*from muc#user, because it is the same except continue element*/
        xmpp_muc_user_item(query_tree, tvb, pinfo, item);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

/*Last Activity jabber:iq:last*/
void
xmpp_last_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"seconds", -1, FALSE, TRUE, NULL, NULL},
        {"value", -1, FALSE, TRUE, NULL, NULL}
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(jabber:iq:last) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    if(element->data)
    {
        attr_t *fake_data = ep_init_attr_t(element->data->value, element->data->offset, element->data->length);
        g_hash_table_insert(element->attrs, "value", fake_data);
    }

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(query_tree, element, pinfo, tvb, NULL, 0);
}

/*XEP-0092: Software Version jabber:iq:version*/
void
xmpp_version_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
      proto_item *query_item;
    proto_tree *query_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"name", -1, FALSE, TRUE, NULL, NULL},
        {"version", -1, FALSE, TRUE, NULL, NULL},
        {"os", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *name, *version, *os;

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(jabber:iq:version) ");

    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);

    if((name = steal_element_by_name(element,"name"))!=NULL)
    {
        attr_t *fake_name = ep_init_attr_t(name->data?name->data->value:"", name->offset, name->length);
        g_hash_table_insert(element->attrs, "name", fake_name);
    }

    if((version = steal_element_by_name(element,"version"))!=NULL)
    {
        attr_t *fake_version = ep_init_attr_t(version->data?version->data->value:"", version->offset, version->length);
        g_hash_table_insert(element->attrs, "version", fake_version);
    }

    if((os = steal_element_by_name(element,"os"))!=NULL)
    {
        attr_t *fake_os = ep_init_attr_t(os->data?os->data->value:"", os->offset, os->length);
        g_hash_table_insert(element->attrs, "os", fake_os);
    }

    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(query_tree, element, pinfo, tvb, NULL, 0);
}
/*XEP-0199: XMPP Ping*/
void
xmpp_ping(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *ping_item;
    proto_tree *ping_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "PING ");

    ping_item = proto_tree_add_item(tree, hf_xmpp_ping, tvb, element->offset, element->length, FALSE);
    ping_tree = proto_item_add_subtree(ping_item, ett_xmpp_ping);

    display_attrs(ping_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(ping_tree, element, pinfo, tvb, NULL, 0);
}

/*XEP-0300: Use of Cryptographic Hash Functions in XMPP urn:xmpp:hashes:0*/
void
xmpp_hashes(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element) {
    proto_item *hashes_item;
    proto_tree *hashes_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
    };
    elem_info elems_info[] = {
        {NAME, "hash", xmpp_hashes_hash, MANY}
    };

    hashes_item = proto_tree_add_item(tree, hf_xmpp_hashes, tvb, element->offset, element->length, FALSE);
    hashes_tree = proto_item_add_subtree(hashes_item, ett_xmpp_hashes);

    display_attrs(hashes_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(hashes_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_hashes_hash(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *hash_item;
    proto_tree *hash_tree;

    attr_info attrs_info[] = {
        {"algo", -1, TRUE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    attr_t *fake_cdata = ep_init_attr_t(elem_cdata(element), element->offset, element->length);
    g_hash_table_insert(element->attrs, "value", fake_cdata);

    hash_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "HASH");
    hash_tree = proto_item_add_subtree(hash_item, ett_xmpp_hashes_hash);
    
    display_attrs(hash_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(hash_tree, element, pinfo, tvb, NULL, 0);
}

/*http://jitsi.org/protocol/inputevt*/
void
xmpp_jitsi_inputevt(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *inputevt_item;
    proto_tree *inputevt_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"action", -1, FALSE, TRUE, NULL, NULL}
    };

    elem_info elems_info[] = {
        {NAME, "remote-control", xmpp_jitsi_inputevt_rmt_ctrl, MANY}
    };

    inputevt_item = proto_tree_add_item(tree, hf_xmpp_jitsi_inputevt, tvb, element->offset, element->length, FALSE);
    inputevt_tree = proto_item_add_subtree(inputevt_item, ett_xmpp_jitsi_inputevt);
    
    display_attrs(inputevt_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(inputevt_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jitsi_inputevt_rmt_ctrl(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *rmt_ctrl_item;
    proto_tree *rmt_ctrl_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"action", -1, TRUE, TRUE, NULL, NULL},
        {"x", -1, FALSE, TRUE, NULL, NULL},
        {"y", -1, FALSE, TRUE, NULL, NULL},
        {"btns", -1, FALSE, TRUE, NULL, NULL},
        {"keycode", -1, FALSE, TRUE, NULL, NULL},
    };

    element_t *action;
    const gchar *action_names[] = {"mouse-move","mouse-press", "mouse-release", "key-press", "key-release"};

    if((action = steal_element_by_names(element, action_names, array_length(action_names)))!=NULL)
    {
        attr_t *fake_action = ep_init_attr_t(action->name, action->offset, action->length);
        g_hash_table_insert(element->attrs,"action", fake_action);

        if(strcmp(action->name,"mouse-move") == 0)
        {
            attr_t *x = get_attr(action,"x");
            attr_t *y = get_attr(action,"y");

            if(x)
                g_hash_table_insert(element->attrs,"x",x);
            if(y)
                g_hash_table_insert(element->attrs,"y",y);
        } else if(strcmp(action->name,"mouse-press") == 0 || strcmp(action->name,"mouse-release") == 0)
        {
            attr_t *btns = get_attr(action,"btns");

            if(btns)
                g_hash_table_insert(element->attrs,"btns",btns);
        } else if(strcmp(action->name,"key-press") == 0 || strcmp(action->name,"key-release") == 0)
        {
            attr_t *keycode = get_attr(action,"keycode");

            if(keycode)
                g_hash_table_insert(element->attrs,"keycode",keycode);
        }

    }

    rmt_ctrl_item = proto_tree_add_item(tree, hf_xmpp_jitsi_inputevt_rmt_ctrl, tvb, element->offset, element->length, FALSE);
    rmt_ctrl_tree = proto_item_add_subtree(rmt_ctrl_item, ett_xmpp_jitsi_inputevt_rmt_ctrl);

    display_attrs(rmt_ctrl_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(rmt_ctrl_tree, element, pinfo, tvb, NULL, 0);
}