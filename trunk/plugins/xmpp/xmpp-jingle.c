/* urn:xmpp:jingle:1
 * urn:xmpp:jingle:apps:rtp:1
 * urn:xmpp:jingle:apps:rtp:errors:1
 * urn:xmpp:jingle:apps:rtp:info:1
 * urn:xmpp:jingle:apps:rtp:rtp-hdrext:0
 * urn:xmpp:jingle:apps:rtp:izrtp:1
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <stdio.h>

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-xml.h>

#include <plugins/xmpp/packet-xmpp.h>
#include <plugins/xmpp/xmpp.h>
#include <plugins/xmpp/xmpp-jingle.h>

void xmpp_iq_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_iq_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_content_description(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_payload_param(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_enc(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_enc_zrtp_hash(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_enc_crypto(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_bandwidth(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_desc_rtp_hdrext(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_iq_jingle_cont_trans(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_iq_jingle_cont_trans_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_cont_trans_remote_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_iq_jingle_rtp_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

void
xmpp_iq_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *jingle_item;
    proto_tree *jingle_tree;

    const gchar *rtp_info_msgs[] = {"active", "hold", "mute", "ringing", "unhold", "unmute"};

    const gchar *action_enums[] = {"content-accept","content-add", "content-modify",
        "content-modify", "content-remove", "description-info", "security-info",
        "session-accept", "session-info", "session-initiate", "session-terminate",
        "transport-accept", "transport-info", "transport-reject", "transport-replace"
    };

    array_t *action_array = ep_init_array_t(action_enums,sizeof(action_enums)/sizeof(gchar*));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"action", hf_xmpp_iq_jingle_action, TRUE, TRUE, val_enum_list, action_array},
        {"sid", hf_xmpp_iq_jingle_sid, TRUE, FALSE, NULL, NULL},
        {"initiator", hf_xmpp_iq_jingle_initiator, FALSE, FALSE, NULL, NULL},
        {"responder", hf_xmpp_iq_jingle_responder, FALSE, FALSE, NULL, NULL}
    };

    element_t *content; /*0-inf*/
    element_t *reason; /*0-1*/
    element_t *rtp_info;

    jingle_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle, tvb, element->offset, element->length, FALSE);
    jingle_tree = proto_item_add_subtree(jingle_item, ett_xmpp_iq_jingle);

    display_attrs(jingle_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((content=steal_element_by_name(element, "content"))!=NULL)
    {
        xmpp_iq_jingle_content(jingle_tree, tvb, pinfo, content);
    }

    while((reason=steal_element_by_name(element, "reason"))!=NULL)
    {
        xmpp_iq_jingle_reason(jingle_tree, tvb, pinfo, reason);
    }

    if((rtp_info = steal_element_by_names(element, rtp_info_msgs, array_length(rtp_info_msgs)))!=NULL)
    {
        xmpp_iq_jingle_rtp_info(jingle_tree, tvb, pinfo, rtp_info);
    }

    xmpp_unknown(jingle_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *content_item;
    proto_tree *content_tree;

    const gchar *creator_enums[] = {"initiator","responder"};
    array_t *creator_enums_array = ep_init_array_t(creator_enums,array_length(creator_enums));

    attr_info attrs_info[] = {
        {"creator", hf_xmpp_iq_jingle_content_creator, TRUE, FALSE, val_enum_list, creator_enums_array},
        {"name", hf_xmpp_iq_jingle_content_name, TRUE, TRUE, NULL, NULL},
        {"disposition", hf_xmpp_iq_jingle_content_disposition, FALSE, FALSE, NULL, NULL},
        {"senders", hf_xmpp_iq_jingle_content_senders, FALSE, FALSE, NULL, NULL}
    };

    element_t *description, *transport;

    content_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_content, tvb, element->offset, element->length, FALSE);
    content_tree = proto_item_add_subtree(content_item, ett_xmpp_iq_jingle_content);

    display_attrs(content_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((description = steal_element_by_name(element, "description"))!=NULL)
        xmpp_iq_jingle_content_description(content_tree, tvb, pinfo, description);

    while((transport = steal_element_by_name(element, "transport"))!=NULL)
        xmpp_iq_jingle_cont_trans(content_tree, tvb, pinfo, transport);

    xmpp_unknown(content_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_content_description(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"media", hf_xmpp_iq_jingle_content_description_media, TRUE, TRUE, NULL, NULL},
        {"ssrc", hf_xmpp_iq_jingle_content_description_ssrc , FALSE, TRUE, NULL, NULL}
    };

    element_t *payload, *encryption, *rtp_hdr, *bandwidth, *zrtp_hash /*IMHO it shouldn't appear in description*/;

    desc_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_content_description, tvb, element->offset, element->length, FALSE);
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_iq_jingle_content_description);

    display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((payload = steal_element_by_name(element, "payload-type"))!=NULL)
        xmpp_iq_jingle_cont_desc_payload(desc_tree, tvb, pinfo, payload);

    if((bandwidth= steal_element_by_name(element, "bandwidth"))!=NULL)
        xmpp_iq_jingle_cont_desc_bandwidth(desc_tree, tvb, pinfo, bandwidth);

    if((encryption = steal_element_by_name(element, "encryption"))!=NULL)
        xmpp_iq_jingle_cont_desc_enc(desc_tree, tvb, pinfo, encryption);

    while((rtp_hdr = steal_element_by_name(element, "rtp-hdrext"))!=NULL)
        xmpp_iq_jingle_cont_desc_rtp_hdrext(desc_tree, tvb, pinfo, rtp_hdr);

    while((zrtp_hash = steal_element_by_name(element,"zrtp-hash"))!=NULL)
        xmpp_iq_jingle_cont_desc_enc_zrtp_hash(desc_tree, tvb, pinfo, zrtp_hash);


    xmpp_unknown(desc_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *payload_item;
    proto_tree *payload_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_iq_jingle_cont_desc_payload_id, TRUE, TRUE, NULL, NULL},
        {"channels", hf_xmpp_iq_jingle_cont_desc_payload_channels, FALSE, FALSE, NULL, NULL},
        {"clockrate", hf_xmpp_iq_jingle_cont_desc_payload_clockrate, FALSE, FALSE, NULL, NULL},
        {"maxptime", hf_xmpp_iq_jingle_cont_desc_payload_maxptime, FALSE, FALSE, NULL, NULL},
        {"name", hf_xmpp_iq_jingle_cont_desc_payload_name, FALSE, TRUE, NULL, NULL},
        {"ptime", hf_xmpp_iq_jingle_cont_desc_payload_ptime, FALSE, FALSE, NULL, NULL}
    };

    element_t *param;

    payload_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_payload, tvb, element->offset, element->length, FALSE);
    payload_tree = proto_item_add_subtree(payload_item, ett_xmpp_iq_jingle_cont_desc_payload);

    display_attrs(payload_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((param = steal_element_by_name(element,"parameter"))!=NULL)
    {
        xmpp_iq_jingle_cont_desc_payload_param(payload_tree, tvb, pinfo, param);
    }

    xmpp_unknown(payload_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_payload_param(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *param_item;
    proto_tree *param_tree;

    proto_item *parent_item;
    attr_t *name, *value;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"name", hf_xmpp_iq_jingle_cont_desc_payload_param_name, TRUE, TRUE, NULL, NULL},
        {"value", hf_xmpp_iq_jingle_cont_desc_payload_param_value, TRUE, TRUE, NULL, NULL}
    };


    name = g_hash_table_lookup(element->attrs, "name");
    value = g_hash_table_lookup(element->attrs, "value");

    if(name && value)
    {
        gchar *parent_item_label;
        //gchar *new_parent_item_label;

        parent_item = proto_tree_get_parent(tree);

        parent_item_label = proto_item_get_text(parent_item);

        if(parent_item_label)
        {
            parent_item_label[strlen(parent_item_label)-1]= '\0';
            proto_item_set_text(parent_item, "%s param(\"%s\")=%s]", parent_item_label ,name->value, value->value);
        }
    }

    param_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_payload_param, tvb, element->offset, element->length, FALSE);
    param_tree = proto_item_add_subtree(param_item, ett_xmpp_iq_jingle_cont_desc_payload_param);

    display_attrs(param_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

}

static void
xmpp_iq_jingle_cont_desc_enc(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *enc_item;
    proto_tree *enc_tree;

    element_t *zrtp_hash, *crypto;

    enc_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_enc, tvb, element->offset, element->length, FALSE);
    enc_tree = proto_item_add_subtree(enc_item, ett_xmpp_iq_jingle_cont_desc_enc);

    while((zrtp_hash = steal_element_by_name(element,"zrtp-hash"))!=NULL)
    {
        xmpp_iq_jingle_cont_desc_enc_zrtp_hash(enc_tree, tvb, pinfo, zrtp_hash);
    }

    while((crypto = steal_element_by_name(element,"crypto"))!=NULL)
    {
        xmpp_iq_jingle_cont_desc_enc_crypto(enc_tree, tvb, pinfo, crypto);
    }

    xmpp_unknown(enc_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_enc_zrtp_hash(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *zrtp_hash_item;
    proto_tree *zrtp_hash_tree;

     attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"version", -1, TRUE, TRUE,NULL,NULL},
        {"hash", -1, TRUE, FALSE, NULL, NULL}
    };

    zrtp_hash_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_enc_zrtp_hash, tvb, element->offset, element->length, FALSE);
    zrtp_hash_tree = proto_item_add_subtree(zrtp_hash_item, ett_xmpp_iq_jingle_cont_desc_enc_zrtp_hash);

    if(element->data)
    {
        attr_t *fake_hash = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "hash", fake_hash);
    }

    display_attrs(zrtp_hash_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(zrtp_hash_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_enc_crypto(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *crypto_item;
    proto_tree *crypto_tree;

     attr_info attrs_info[] = {
        {"crypto-suite", -1, TRUE, TRUE, NULL, NULL},
        {"key-params", -1, TRUE, FALSE,NULL,NULL},
        {"session-params", -1, FALSE, TRUE, NULL, NULL},
        {"tag", -1, TRUE, FALSE, NULL, NULL}
    };

    crypto_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_enc_crypto, tvb, element->offset, element->length, FALSE);
    crypto_tree = proto_item_add_subtree(crypto_item, ett_xmpp_iq_jingle_cont_desc_enc_crypto);


    display_attrs(crypto_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(crypto_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_desc_bandwidth(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *bandwidth_item;
    proto_tree *bandwidth_tree;

    attr_info attrs_info[] = {
        {"type", -1, TRUE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    bandwidth_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_bandwidth, tvb, element->offset, element->length, FALSE);
    bandwidth_tree = proto_item_add_subtree(bandwidth_item, ett_xmpp_iq_jingle_cont_desc_bandwidth);

    if(element->data)
    {
        attr_t *fake_value = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_value);
    }

    display_attrs(bandwidth_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
}

static void
xmpp_iq_jingle_cont_desc_rtp_hdrext(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *rtp_hdr_item;
    proto_tree *rtp_hdr_tree;

    const gchar *senders[] = {"both", "initiator", "responder"};
    array_t *senders_enums = ep_init_array_t(senders, 3);

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"id", -1, TRUE, FALSE, NULL, NULL},
        {"uri", -1, TRUE, TRUE, NULL, NULL},
        {"senders", -1, FALSE, TRUE, val_enum_list, senders_enums}
    };

    rtp_hdr_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_desc_rtp_hdr, tvb, element->offset, element->length, FALSE);
    rtp_hdr_tree = proto_item_add_subtree(rtp_hdr_item, ett_xmpp_iq_jingle_cont_desc_rtp_hdr);

    display_attrs(rtp_hdr_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

}

static void
xmpp_iq_jingle_cont_trans(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"pwd", hf_xmpp_iq_jingle_cont_trans_pwd, FALSE, FALSE, NULL, NULL},
        {"ufrag", hf_xmpp_iq_jingle_cont_trans_ufrag, FALSE, TRUE, NULL, NULL}
    };

    element_t *candidate, *remote_candidate;

    trans_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_trans, tvb, element->offset, element->length, FALSE);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_iq_jingle_cont_trans);

    display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    while((candidate = steal_element_by_name(element, "candidate"))!=NULL)
    {
        xmpp_iq_jingle_cont_trans_candidate(trans_tree, tvb, pinfo, candidate);
    }

    while((remote_candidate = steal_element_by_name(element, "remote-candidate"))!=NULL)
    {
        xmpp_iq_jingle_cont_trans_remote_candidate(trans_tree, tvb, pinfo, remote_candidate);
    }

    xmpp_unknown(trans_tree, tvb, pinfo, element);

}

static void
xmpp_iq_jingle_cont_trans_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    const gchar *type_enums[] = {"host", "prflx", "relay", "srflx"};
    array_t *type_enums_array = ep_init_array_t(type_enums,array_length(type_enums));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"component", -1, TRUE, FALSE, NULL, NULL},
        {"foundation", -1, TRUE, FALSE, NULL, NULL},
        {"generation", -1, TRUE, FALSE, NULL, NULL},
        {"id", -1, FALSE, FALSE, NULL, NULL}, /*in schemas id is marked as required, but in jitsi logs it doesn't appear*/
        {"ip", -1, TRUE, FALSE, NULL, NULL},
        {"network", -1, TRUE, FALSE, NULL, NULL},
        {"port", -1, TRUE, FALSE, NULL, NULL},
        {"priority", -1, TRUE, FALSE, NULL, NULL},
        {"protocol", -1, TRUE, TRUE, NULL, NULL},
        {"rel-addr", -1, FALSE, FALSE, NULL, NULL},
        {"rel-port", -1, FALSE, FALSE, NULL, NULL},
        {"type", -1, TRUE, TRUE, val_enum_list, type_enums_array}
    };

    cand_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_trans_cand, tvb, element->offset, element->length, FALSE);
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_iq_jingle_cont_trans_cand);

    display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(cand_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_cont_trans_remote_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *remote_cand_item;
    proto_tree *remote_cand_tree;

    attr_info attrs_info[] = {
        {"component", -1, TRUE, FALSE, NULL, NULL},
        {"ip", -1, TRUE, FALSE, NULL, NULL},
        {"port", -1, TRUE, FALSE, NULL, NULL}
    };

    remote_cand_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_cont_trans_rem_cand, tvb, element->offset, element->length, FALSE);
    remote_cand_tree = proto_item_add_subtree(remote_cand_item, ett_xmpp_iq_jingle_cont_trans_rem_cand);

    display_attrs(remote_cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(remote_cand_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *reason_item;
    proto_tree *reason_tree;

    attr_info attrs_info[] = {
        {"condition", hf_xmpp_iq_jingle_reason_condition, TRUE, TRUE, NULL, NULL},
        {"sid", -1, FALSE, TRUE, NULL, NULL},
        {"rtp-error", -1, FALSE, TRUE, NULL, NULL},
        {"text", hf_xmpp_iq_jingle_reason_text, FALSE, FALSE, NULL, NULL}
   };

    element_t *condition; /*1?*/
    element_t *text; /*0-1*/
    element_t *rtp_error;

    const gchar *reason_names[] = { "success", "busy", "failed-application", "cancel", "connectivity-error",
        "decline", "expired", "failed-transport", "general-error", "gone", "incompatible-parameters",
        "media-error", "security-error", "timeout", "unsupported-applications", "unsupported-transports"};

    const gchar *rtp_error_names[] = {"crypto-required", "invalid-crypto"};

    reason_item = proto_tree_add_item(tree, hf_xmpp_iq_jingle_reason, tvb, element->offset, element->length, FALSE);
    reason_tree = proto_item_add_subtree(reason_item, ett_xmpp_iq_jingle_reason);


    /*Looks for reason description. "alternative-session" may contain "sid" element
     Elements are changed into attribute*/
    if((condition = steal_element_by_names(element, reason_names, array_length(reason_names)))!=NULL)
    {
        attr_t *fake_cond = ep_init_attr_t(condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, "condition", fake_cond);

    } else if((condition = steal_element_by_name(element, "alternative-session"))!=NULL)
    {
        attr_t *fake_cond,*fake_alter_sid;
        element_t *sid;

        fake_cond = ep_init_attr_t(condition->name, condition->offset, condition->length);
        g_hash_table_insert(element->attrs, "condition", fake_cond);


        if((sid = steal_element_by_name(condition, "sid"))!=NULL)
        {
            fake_alter_sid = ep_init_attr_t(sid->name, sid->offset, sid->length);
            g_hash_table_insert(element->attrs, "sid", fake_alter_sid);
        }
    }

    if((rtp_error = steal_element_by_names(element, rtp_error_names, array_length(rtp_error_names)))!=NULL)
    {
        attr_t *fake_rtp_error = ep_init_attr_t(rtp_error->name, rtp_error->offset, rtp_error->length);
        g_hash_table_insert(element->attrs, "rtp-error", fake_rtp_error);
    }

    if((text = steal_element_by_name(element, "text"))!=NULL)
    {
        attr_t *fake_text = ep_init_attr_t(text->data?text->data->value:"", text->offset, text->length);
        g_hash_table_insert(element->attrs, "text", fake_text);
    }

    display_attrs(reason_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(reason_tree, tvb, pinfo, element);
}

static void
xmpp_iq_jingle_rtp_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *rtp_info_item;
    proto_tree *rtp_info_tree;

    const gchar *creator[] = {"initiator","responder"};
    array_t *creator_enums = ep_init_array_t(creator, array_length(creator));

    attr_info mute_attrs_info[] = {
        {"creator", -1, TRUE, TRUE, val_enum_list, creator_enums},
        {"name", -1, TRUE, TRUE, NULL, NULL}
    };

    rtp_info_item = proto_tree_add_string(tree, hf_xmpp_iq_jingle_rtp_info, tvb, element->offset, element->length, element->name);
    rtp_info_tree = proto_item_add_subtree(rtp_info_item, ett_xmpp_iq_jingle_rtp_info);

    if(strcmp("mute", element->name) == 0 || strcmp("unmute", element->name) == 0)
        display_attrs(rtp_info_tree, element, pinfo, tvb, mute_attrs_info, array_length(mute_attrs_info));
}
