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

void xmpp_iq_bind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
void xmpp_iq_services(proto_tree *tree, tvbuff_t *tvb, element_t *element);
void xmpp_iq_session(proto_tree *tree, tvbuff_t *tvb, element_t *element);

void xmpp_vcard(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
void xmpp_vcard_x_update(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void xmpp_iq_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_disco_items_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element);
static void xmpp_disco_info_identity(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element);
static void xmpp_disco_info_feature(proto_tree *tree, tvbuff_t *tvb, element_t *element);

static void xmpp_bytestreams_streamhost(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_bytestreams_streamhost_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_bytestreams_activate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_bytestreams_udpsuccess(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void xmpp_si(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_si_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_si_file_range(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
void xmpp_feature_neg(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

static void xmpp_x_data_field(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_x_data_field_option(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_x_data_field_value(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

void xmpp_ibb_open(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
void xmpp_ibb_close(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
void xmpp_ibb_data(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void xmpp_delay(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
void xmpp_presence_caps(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void xmpp_vcard_x_update(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void
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
        fake_attr_res->value = resource->data?resource->data->value:"";
        fake_attr_res->offset = resource->offset;
        fake_attr_res->length = resource->length;
        g_hash_table_insert(element->attrs, "resource", fake_attr_res);
    }

    if(jid)
    {
        attr_t *fake_attr_jid = ep_alloc(sizeof(attr_t));
        fake_attr_jid->value = jid->data?jid->data->value:"";
        fake_attr_jid->offset = jid->offset;
        fake_attr_jid->length = jid->length;
        g_hash_table_insert(element->attrs, "jid", fake_attr_jid);
    }

    display_attrs(bind_tree, bind_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(bind_tree, tvb, pinfo, element);
}

void
xmpp_iq_services(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    proto_item *services_item;

    attr_t *xmlns = g_hash_table_lookup(element->attrs, "xmlns");

    services_item = proto_tree_add_string_format(tree, hf_xmpp_iq_services, tvb, element->offset, element->length, xmlns?xmlns->value:"", "SERVICES (%s)", xmlns?xmlns->value:"");
}

void
xmpp_iq_session(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{
    attr_t *xmlns  = g_hash_table_lookup(element->attrs, "xmlns");
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

    vcard_item = proto_tree_add_item(tree, hf_xmpp_vcard, tvb, element->offset, element->length, FALSE);\
    vcard_tree = proto_item_add_subtree(vcard_item, ett_xmpp_vcard);

    cdata = get_first_element(element);

    if(cdata)
    {
        attr_t *fake_cdata = ep_init_attr_t(element_to_string(tvb, cdata), cdata->offset, cdata->length);
        g_hash_table_insert(element->attrs,"value", fake_cdata);
    }
    display_attrs(vcard_tree, vcard_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    display_attrs(x_tree, x_item, element,pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(x_tree, tvb, pinfo, element);
}

/*disco#info disco#items*/
void
xmpp_iq_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;

    const gchar *mode_enums[] = {"tcp", "udp"};
    array_t *mode_array = ep_init_array_t(mode_enums, array_length(mode_enums));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"node", hf_xmpp_iq_query_node, FALSE, TRUE, NULL, NULL},
        {"sid", -1, FALSE, TRUE, NULL, NULL},
        {"mode", -1, FALSE, TRUE, val_enum_list, mode_array},
        {"dstaddr", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *item, *identity, *feature,
            *streamhost, *streamhost_used, *activate, *udpsuccess, *x_data;

    query_item = proto_tree_add_item(tree, hf_xmpp_iq_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_iq_query);

    display_attrs(query_tree, query_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((item = steal_element_by_name(element, "item")) != NULL)
    {
        xmpp_disco_items_item(query_tree, tvb, pinfo, item);
    }

    while((identity = steal_element_by_name(element, "identity")) != NULL)
    {
        xmpp_disco_info_identity(query_tree, tvb, pinfo, identity);
    }

    while((feature = steal_element_by_name(element, "feature")) != NULL)
    {
        xmpp_disco_info_feature(query_tree, tvb, feature);
    }

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

    if((x_data = steal_element_by_name_and_attr(element, "x", "xmlns", "jabber:x:data")) != NULL)
    {
        xmpp_x_data(query_tree, tvb, pinfo, x_data);
    }

    xmpp_unknown(query_tree, tvb, pinfo, element);
}

static void
xmpp_disco_items_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;

    const gchar *ask_enums[] = {"subscribe"};
    const gchar *subscription_enums[] = {"both","from","none","remove","to"};

    array_t *ask_enums_array = ep_init_array_t(ask_enums,array_length(ask_enums));
    array_t *subscription_array = ep_init_array_t(subscription_enums,array_length(subscription_enums));

    attr_info attrs_info[] = {
        {"jid", hf_xmpp_iq_query_item_jid, TRUE, TRUE, NULL, NULL},
        {"name", hf_xmpp_iq_query_item_name, FALSE, TRUE, NULL, NULL},
        {"node", hf_xmpp_iq_query_item_node, FALSE, TRUE, NULL, NULL},
        {"ask", hf_xmpp_iq_query_item_ask, FALSE, TRUE, val_enum_list, ask_enums_array},
        {"approved", hf_xmpp_iq_query_item_approved, FALSE, TRUE, NULL, NULL},
        {"subscription", hf_xmpp_iq_query_item_subscription, FALSE, TRUE, val_enum_list, subscription_array},
        {"group", hf_xmpp_iq_query_item_group, FALSE, TRUE, NULL, NULL}
    };


    element_t *group;
    attr_t *fake_attr_group;

    group = steal_element_by_name(element,"group");
    if(group)
    {
        fake_attr_group = ep_alloc(sizeof(attr_t));
        fake_attr_group->value = group->data?group->data->value:"";
        fake_attr_group->offset = group->offset;
        fake_attr_group->length = group->length;
        g_hash_table_insert(element->attrs,"group",fake_attr_group);
    }

    item_item = proto_tree_add_item(tree, hf_xmpp_iq_query_item, tvb, element->offset, element->length, FALSE);
    item_tree = proto_item_add_subtree(item_item, ett_xmpp_iq_query_item);

    display_attrs(item_tree, item_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));
}

static void
xmpp_disco_info_identity(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
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

    display_attrs(identity_tree, identity_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

}

static void
xmpp_disco_info_feature(proto_tree *tree, tvbuff_t *tvb, element_t *element)
{

    attr_t *var = g_hash_table_lookup(element->attrs, "var");

    if(var)
    {
        proto_tree_add_string_format(tree, hf_xmpp_iq_query_feature, tvb, var->offset, var->length, var->value, "FEATURE [%s]", var->value);
    }
}


/*bytestreams*/
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

    sh_item = proto_tree_add_item(tree, hf_xmpp_iq_query_streamhost, tvb, element->offset, element->length, FALSE);
    sh_tree = proto_item_add_subtree(sh_item, ett_xmpp_iq_query_streamhost);

    display_attrs(sh_tree, sh_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    shu_item = proto_tree_add_item(tree, hf_xmpp_iq_query_streamhost_used, tvb, element->offset, element->length, FALSE);
    shu_tree = proto_item_add_subtree(shu_item, ett_xmpp_iq_query_streamhost_used);

    display_attrs(shu_tree, shu_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(shu_tree, tvb, pinfo, element);
}

static void
xmpp_bytestreams_activate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_tree_add_item(tree, hf_xmpp_iq_query_activate, tvb, element->offset, element->length, FALSE);
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

    udps_item = proto_tree_add_item(tree, hf_xmpp_iq_query_udpsuccess, tvb, element->offset, element->length, FALSE);
    udps_tree =proto_item_add_subtree(udps_item, ett_xmpp_iq_query_udpsuccess);

    display_attrs(udps_tree, udps_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    si_item = proto_tree_add_item(tree, hf_xmpp_iq_si, tvb, element->offset, element->length, FALSE);
    si_tree = proto_item_add_subtree(si_item, ett_xmpp_iq_si);

    display_attrs(si_tree, si_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    file_item = proto_tree_add_item(tree, hf_xmpp_iq_si_file, tvb, element->offset, element->length, FALSE);
    file_tree = proto_item_add_subtree(file_item, ett_xmpp_iq_si_file);

    if((desc = steal_element_by_name(element, "desc"))!=NULL)
    {
         attr_t *fake_desc = ep_init_attr_t(desc->data?desc->data->value:"", desc->offset, desc->length);
         g_hash_table_insert(element->attrs, "desc", fake_desc);
    }

    if((range = steal_element_by_name(element, "range"))!=NULL)
    {
        xmpp_si_file_range(file_tree, tvb, pinfo, range);
    }

    display_attrs(file_tree, file_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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
    range_tree = proto_item_add_subtree(range_item, ett_xmpp_iq_si_file_range);

    display_attrs(range_tree, range_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    display_attrs(feature_tree, feature_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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
        {"type", -1, TRUE, TRUE, val_enum_list, type_array}
    };

    element_t *field; /*TODO instructions, title, reported, item*/

    x_item = proto_tree_add_item(tree, hf_xmpp_x_data, tvb, element->offset, element->length, FALSE);
    x_tree = proto_item_add_subtree(x_item, ett_xmpp_x_data);

    display_attrs(x_tree, x_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    display_attrs(field_tree, field_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    display_attrs(option_tree, option_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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


    display_attrs(value_tree, value_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    open_item = proto_tree_add_item(tree, hf_xmpp_ibb_open, tvb, element->offset, element->length, FALSE);
    open_tree = proto_item_add_subtree(open_item, ett_xmpp_ibb_open);

    display_attrs(open_tree, open_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));
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

    close_item = proto_tree_add_item(tree, hf_xmpp_ibb_close, tvb, element->offset, element->length, FALSE);
    close_tree = proto_item_add_subtree(close_item, ett_xmpp_ibb_close);

    display_attrs(close_tree, close_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));
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

    data_item = proto_tree_add_item(tree, hf_xmpp_ibb_data, tvb, element->offset, element->length, FALSE);
    data_tree = proto_item_add_subtree(data_item, ett_xmpp_ibb_data);

    if(element->data)
    {
        attr_t *fake_data = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_data);
    }

    display_attrs(data_tree, data_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(data_tree, tvb, pinfo, element);
}


/*Delayed Delivery urn:xmpp:delay*/
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

    display_attrs(delay_tree, delay_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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

    display_attrs(caps_tree, caps_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

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
    

    display_attrs(x_tree, x_item, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(x_tree, tvb, pinfo, element);
}