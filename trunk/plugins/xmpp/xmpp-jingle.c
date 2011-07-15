/* urn:xmpp:jingle:1
 * urn:xmpp:jingle:apps:rtp:1
 * urn:xmpp:jingle:apps:rtp:errors:1
 * urn:xmpp:jingle:apps:rtp:info:1
 * urn:xmpp:jingle:apps:rtp:rtp-hdrext:0
 * urn:xmpp:jingle:apps:rtp:izrtp:1
 *
 * urn:xmpp:jingle:transports:ice-udp:1
 * urn:xmpp:jingle:transports:raw-udp:1
 * urn:xmpp:jingle:transports:s5b:1
 * urn:xmpp:jingle:transports:ibb:1
 *
 * http://jabber.org/protocol/jinglenodes
 * http://jabber.org/protocol/jinglenodes#channel
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
#include <plugins/xmpp/xmpp-conference.h>
#include <plugins/xmpp/xmpp-gtalk.h>
#include <plugins/xmpp/xmpp-other.h>

void xmpp_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_content_description_rtp(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_cont_desc_rtp_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_cont_desc_rtp_payload_param(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_jingle_cont_desc_rtp_enc(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_jingle_cont_desc_rtp_enc_zrtp_hash(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_jingle_cont_desc_rtp_enc_crypto(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_jingle_cont_desc_rtp_bandwidth(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_jingle_cont_desc_rtp_hdrext(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element);
static void xmpp_jingle_cont_trans_ice(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_ice_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_cont_trans_ice_remote_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_rtp_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jinglenodes_relay_stun_tracker(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_raw(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_raw_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_cont_trans_s5b(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_s5b_candidate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_s5b_activated(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_s5b_cand_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_s5b_cand_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_s5b_proxy_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_jingle_cont_trans_ibb(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

static void xmpp_jingle_file_transfer_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_file_transfer_offer(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_file_transfer_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_file_transfer_request(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_file_transfer_received(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_file_transfer_abort(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
static void xmpp_jingle_file_transfer_checksum(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

/*XEP-0166: Jingle urn:xmpp:jingle:1*/
void
xmpp_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *jingle_item;
    proto_tree *jingle_tree;

    const gchar *rtp_info_msgs[] = {"active", "hold", "mute", "ringing", "unhold", "unmute"};

    const gchar *action_enums[] = {"content-accept","content-add", "content-modify",
        "content-modify", "content-remove", "description-info", "security-info",
        "session-accept", "session-info", "session-initiate", "session-terminate",
        "transport-accept", "transport-info", "transport-reject", "transport-replace"
    };

    array_t *action_array = ep_init_array_t(action_enums,array_length(action_enums));
    array_t *rtp_info_array = ep_init_array_t(rtp_info_msgs, array_length(rtp_info_msgs));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"action", hf_xmpp_jingle_action, TRUE, TRUE, val_enum_list, action_array},
        {"sid", hf_xmpp_jingle_sid, TRUE, FALSE, NULL, NULL},
        {"initiator", hf_xmpp_jingle_initiator, FALSE, FALSE, NULL, NULL},
        {"responder", hf_xmpp_jingle_responder, FALSE, FALSE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME, "content", xmpp_jingle_content, MANY},
        {NAME, "reason", xmpp_jingle_reason, MANY},
        {NAMES, rtp_info_array, xmpp_jingle_rtp_info, ONE},
        {NAME, "conference-info", xmpp_conferece_info_advert, ONE}
    };

     attr_t *action = get_attr(element,"action");
     col_append_fstr(pinfo->cinfo, COL_INFO, "JINGLE(%s) ", action?action->value:"");


    jingle_item = proto_tree_add_item(tree, hf_xmpp_jingle, tvb, element->offset, element->length, FALSE);
    jingle_tree = proto_item_add_subtree(jingle_item, ett_xmpp_jingle);

    display_attrs(jingle_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(jingle_item, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_content(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *content_item;
    proto_tree *content_tree;

    const gchar *creator_enums[] = {"initiator","responder"};
    array_t *creator_enums_array = ep_init_array_t(creator_enums,array_length(creator_enums));

    attr_info attrs_info[] = {
        {"creator", hf_xmpp_jingle_content_creator, TRUE, FALSE, val_enum_list, creator_enums_array},
        {"name", hf_xmpp_jingle_content_name, TRUE, TRUE, NULL, NULL},
        {"disposition", hf_xmpp_jingle_content_disposition, FALSE, FALSE, NULL, NULL},
        {"senders", hf_xmpp_jingle_content_senders, FALSE, FALSE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME_AND_ATTR, name_attr_struct("description", "xmlns", "urn:xmpp:jingle:apps:rtp:1"), xmpp_jingle_content_description_rtp, MANY},
        {NAME_AND_ATTR, name_attr_struct("description", "xmlns", "urn:xmpp:jingle:apps:file-transfer:3"), xmpp_jingle_file_transfer_desc, MANY},
        {NAME_AND_ATTR,  name_attr_struct("transport", "xmlns", "urn:xmpp:jingle:transports:ice-udp:1"), xmpp_jingle_cont_trans_ice, MANY},
        {NAME_AND_ATTR,  name_attr_struct("transport", "xmlns", "urn:xmpp:jingle:transports:raw-udp:1"), xmpp_jingle_cont_trans_raw, MANY},
        {NAME_AND_ATTR,  name_attr_struct("transport", "xmlns", "urn:xmpp:jingle:transports:s5b:1"), xmpp_jingle_cont_trans_s5b, MANY},
        {NAME_AND_ATTR,  name_attr_struct("transport", "xmlns", "urn:xmpp:jingle:transports:ibb:1"), xmpp_jingle_cont_trans_ibb, MANY},
        {NAME_AND_ATTR,  name_attr_struct("transport", "xmlns", "http://www.google.com/transport/p2p"), xmpp_gtalk_transport_p2p, MANY},
        {NAME_AND_ATTR,  name_attr_struct("received", "xmlns", "urn:xmpp:jingle:apps:file-transfer:3"), xmpp_jingle_file_transfer_received, MANY},
        {NAME_AND_ATTR,  name_attr_struct("abort", "xmlns", "urn:xmpp:jingle:apps:file-transfer:3"), xmpp_jingle_file_transfer_abort, MANY},
        {NAME_AND_ATTR,  name_attr_struct("checksum", "xmlns", "urn:xmpp:jingle:apps:file-transfer:3"), xmpp_jingle_file_transfer_checksum, MANY},
        {NAME_AND_ATTR, name_attr_struct("inputevt", "xmlns","http://jitsi.org/protocol/inputevt"), xmpp_jitsi_inputevt, ONE},
    };

    content_item = proto_tree_add_item(tree, hf_xmpp_jingle_content, tvb, element->offset, element->length, FALSE);
    content_tree = proto_item_add_subtree(content_item, ett_xmpp_jingle_content);

    display_attrs(content_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(content_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_reason(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *reason_item;
    proto_tree *reason_tree;

    attr_info attrs_info[] = {
        {"condition", hf_xmpp_jingle_reason_condition, TRUE, TRUE, NULL, NULL},
        {"sid", -1, FALSE, TRUE, NULL, NULL},
        {"rtp-error", -1, FALSE, TRUE, NULL, NULL},
        {"text", hf_xmpp_jingle_reason_text, FALSE, FALSE, NULL, NULL}
   };

    element_t *condition; /*1?*/
    element_t *text; /*0-1*/
    element_t *rtp_error;

    const gchar *reason_names[] = { "success", "busy", "failed-application", "cancel", "connectivity-error",
        "decline", "expired", "failed-transport", "general-error", "gone", "incompatible-parameters",
        "media-error", "security-error", "timeout", "unsupported-applications", "unsupported-transports"};

    const gchar *rtp_error_names[] = {"crypto-required", "invalid-crypto"};

    reason_item = proto_tree_add_item(tree, hf_xmpp_jingle_reason, tvb, element->offset, element->length, FALSE);
    reason_tree = proto_item_add_subtree(reason_item, ett_xmpp_jingle_reason);


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

/*XEP-0167: Jingle RTP Sessions urn:xmpp:jingle:apps:rtp:1*/
static void
xmpp_jingle_content_description_rtp(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"media", hf_xmpp_jingle_content_description_media, TRUE, TRUE, NULL, NULL},
        {"ssrc", hf_xmpp_jingle_content_description_ssrc , FALSE, TRUE, NULL, NULL}
    };

    elem_info elems_info[] = {
        {NAME, "payload-type", xmpp_jingle_cont_desc_rtp_payload, MANY},
        {NAME, "bandwidth", xmpp_jingle_cont_desc_rtp_bandwidth, ONE},
        {NAME, "encryption", xmpp_jingle_cont_desc_rtp_enc, ONE},
        {NAME, "rtp-hdrext", xmpp_jingle_cont_desc_rtp_hdrext, MANY},
        {NAME, "zrtp-hash", xmpp_jingle_cont_desc_rtp_enc_zrtp_hash, MANY}/*IMHO it shouldn't appear in description*/
        
    };

    desc_item = proto_tree_add_item(tree, hf_xmpp_jingle_content_description, tvb, element->offset, element->length, FALSE);
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_jingle_content_description);

    display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(desc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_desc_rtp_payload(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *payload_item;
    proto_tree *payload_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"id", hf_xmpp_jingle_cont_desc_payload_id, TRUE, TRUE, NULL, NULL},
        {"channels", hf_xmpp_jingle_cont_desc_payload_channels, FALSE, FALSE, NULL, NULL},
        {"clockrate", hf_xmpp_jingle_cont_desc_payload_clockrate, FALSE, FALSE, NULL, NULL},
        {"maxptime", hf_xmpp_jingle_cont_desc_payload_maxptime, FALSE, FALSE, NULL, NULL},
        {"name", hf_xmpp_jingle_cont_desc_payload_name, FALSE, TRUE, NULL, NULL},
        {"ptime", hf_xmpp_jingle_cont_desc_payload_ptime, FALSE, FALSE, NULL, NULL}
    };

    elem_info elems_info [] =
    {
        {NAME, "parameter", xmpp_jingle_cont_desc_rtp_payload_param, MANY}
    };

    payload_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_payload, tvb, element->offset, element->length, FALSE);
    payload_tree = proto_item_add_subtree(payload_item, ett_xmpp_jingle_cont_desc_payload);

    display_attrs(payload_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(payload_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_desc_rtp_payload_param(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *param_item;
    proto_tree *param_tree;

    proto_item *parent_item;
    attr_t *name, *value;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"name", hf_xmpp_jingle_cont_desc_payload_param_name, TRUE, TRUE, NULL, NULL},
        {"value", hf_xmpp_jingle_cont_desc_payload_param_value, TRUE, TRUE, NULL, NULL}
    };


    name = get_attr(element, "name");
    value = get_attr(element, "value");

    if(name && value)
    {
        gchar *parent_item_label;

        parent_item = proto_tree_get_parent(tree);

        parent_item_label = proto_item_get_text(parent_item);

        if(parent_item_label)
        {
            parent_item_label[strlen(parent_item_label)-1]= '\0';
            proto_item_set_text(parent_item, "%s param(\"%s\")=%s]", parent_item_label ,name->value, value->value);
        }
    }

    param_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_payload_param, tvb, element->offset, element->length, FALSE);
    param_tree = proto_item_add_subtree(param_item, ett_xmpp_jingle_cont_desc_payload_param);

    display_attrs(param_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(param_tree, tvb, pinfo, element);

}

static void
xmpp_jingle_cont_desc_rtp_enc(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *enc_item;
    proto_tree *enc_tree;

    elem_info elems_info [] = {
        {NAME, "zrtp-hash", xmpp_jingle_cont_desc_rtp_enc_zrtp_hash, MANY},
        {NAME, "crypto", xmpp_jingle_cont_desc_rtp_enc_crypto, MANY}
    };

    enc_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_enc, tvb, element->offset, element->length, FALSE);
    enc_tree = proto_item_add_subtree(enc_item, ett_xmpp_jingle_cont_desc_enc);

    display_attrs(enc_tree, element, pinfo, tvb, NULL, 0);
    display_elems(enc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

/*urn:xmpp:jingle:apps:rtp:zrtp:1*/
static void
xmpp_jingle_cont_desc_rtp_enc_zrtp_hash(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *zrtp_hash_item;
    proto_tree *zrtp_hash_tree;

     attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"version", -1, TRUE, TRUE,NULL,NULL},
        {"hash", -1, TRUE, FALSE, NULL, NULL}
    };

    zrtp_hash_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_enc_zrtp_hash, tvb, element->offset, element->length, FALSE);
    zrtp_hash_tree = proto_item_add_subtree(zrtp_hash_item, ett_xmpp_jingle_cont_desc_enc_zrtp_hash);

    if(element->data)
    {
        attr_t *fake_hash = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "hash", fake_hash);
    }

    display_attrs(zrtp_hash_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(zrtp_hash_tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_desc_rtp_enc_crypto(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *crypto_item;
    proto_tree *crypto_tree;

     attr_info attrs_info[] = {
        {"crypto-suite", -1, TRUE, TRUE, NULL, NULL},
        {"key-params", -1, TRUE, FALSE,NULL,NULL},
        {"session-params", -1, FALSE, TRUE, NULL, NULL},
        {"tag", -1, TRUE, FALSE, NULL, NULL}
    };

    crypto_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_enc_crypto, tvb, element->offset, element->length, FALSE);
    crypto_tree = proto_item_add_subtree(crypto_item, ett_xmpp_jingle_cont_desc_enc_crypto);


    display_attrs(crypto_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(crypto_tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_desc_rtp_bandwidth(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *bandwidth_item;
    proto_tree *bandwidth_tree;

    attr_info attrs_info[] = {
        {"type", -1, TRUE, TRUE, NULL, NULL},
        {"value", -1, TRUE, TRUE, NULL, NULL}
    };

    bandwidth_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_bandwidth, tvb, element->offset, element->length, FALSE);
    bandwidth_tree = proto_item_add_subtree(bandwidth_item, ett_xmpp_jingle_cont_desc_bandwidth);

    if(element->data)
    {
        attr_t *fake_value = ep_init_attr_t(element->data->value, element->offset, element->length);
        g_hash_table_insert(element->attrs, "value", fake_value);
    }

    display_attrs(bandwidth_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    xmpp_unknown(bandwidth_tree, tvb, pinfo, element);
}

/*urn:xmpp:jingle:apps:rtp:rtp-hdrext:0*/
static void
xmpp_jingle_cont_desc_rtp_hdrext(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, element_t* element)
{
    proto_item *rtp_hdr_item;
    proto_tree *rtp_hdr_tree;

    const gchar *senders[] = {"both", "initiator", "responder"};
    array_t *senders_enums = ep_init_array_t(senders, 3);

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"id", -1, TRUE, FALSE, NULL, NULL},
        {"uri", -1, TRUE, TRUE, NULL, NULL},
        {"senders", -1, FALSE, TRUE, val_enum_list, senders_enums},
        {"parameter", -1, FALSE, TRUE, NULL, NULL}
    };

    element_t *parameter;

    rtp_hdr_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_desc_rtp_hdr, tvb, element->offset, element->length, FALSE);
    rtp_hdr_tree = proto_item_add_subtree(rtp_hdr_item, ett_xmpp_jingle_cont_desc_rtp_hdr);

    if((parameter = steal_element_by_name(element, "parameter"))!=NULL)
    {
        attr_t *name = get_attr(element, "name");
        attr_t *fake_attr = ep_init_attr_t(name?name->value:"", parameter->offset, parameter->length);
        g_hash_table_insert(element->attrs, "parameter", fake_attr);
    }

    display_attrs(rtp_hdr_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(rtp_hdr_tree, tvb, pinfo, element);
}

/*urn:xmpp:jingle:apps:rtp:info:1*/
static void
xmpp_jingle_rtp_info(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *rtp_info_item;
    proto_tree *rtp_info_tree;

    const gchar *creator[] = {"initiator","responder"};
    array_t *creator_enums = ep_init_array_t(creator, array_length(creator));

    attr_info mute_attrs_info[] = {
        {"creator", -1, TRUE, TRUE, val_enum_list, creator_enums},
        {"name", -1, TRUE, TRUE, NULL, NULL}
    };

    rtp_info_item = proto_tree_add_string(tree, hf_xmpp_jingle_rtp_info, tvb, element->offset, element->length, element->name);
    rtp_info_tree = proto_item_add_subtree(rtp_info_item, ett_xmpp_jingle_rtp_info);

    if(strcmp("mute", element->name) == 0 || strcmp("unmute", element->name) == 0)
        display_attrs(rtp_info_tree, element, pinfo, tvb, mute_attrs_info, array_length(mute_attrs_info));

    xmpp_unknown(rtp_info_tree, tvb, pinfo, element);
}

/*XEP-0176: Jingle ICE-UDP Transport Method urn:xmpp:jingle:transports:ice-udp:1*/
static void
xmpp_jingle_cont_trans_ice(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL},
        {"pwd", hf_xmpp_jingle_cont_trans_pwd, FALSE, FALSE, NULL, NULL},
        {"ufrag", hf_xmpp_jingle_cont_trans_ufrag, FALSE, TRUE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME, "candidate", xmpp_jingle_cont_trans_ice_candidate, MANY},
        {NAME, "remote-candidate", xmpp_jingle_cont_trans_ice_remote_candidate, ONE}
    };

    trans_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans, tvb, element->offset, element->length, FALSE);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_jingle_cont_trans);

    display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    display_elems(trans_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_trans_ice_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
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
        {"ip", -1, TRUE, TRUE, NULL, NULL},
        {"network", -1, TRUE, FALSE, NULL, NULL},
        {"port", -1, TRUE, FALSE, NULL, NULL},
        {"priority", -1, TRUE, TRUE, NULL, NULL},
        {"protocol", -1, TRUE, TRUE, NULL, NULL},
        {"rel-addr", -1, FALSE, FALSE, NULL, NULL},
        {"rel-port", -1, FALSE, FALSE, NULL, NULL},
        {"type", -1, TRUE, TRUE, val_enum_list, type_enums_array}
    };

    cand_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_cand, tvb, element->offset, element->length, FALSE);
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_jingle_cont_trans_cand);

    display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(cand_tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_trans_ice_remote_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *remote_cand_item;
    proto_tree *remote_cand_tree;

    attr_info attrs_info[] = {
        {"component", -1, TRUE, FALSE, NULL, NULL},
        {"ip", -1, TRUE, FALSE, NULL, NULL},
        {"port", -1, TRUE, FALSE, NULL, NULL}
    };

    remote_cand_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_rem_cand, tvb, element->offset, element->length, FALSE);
    remote_cand_tree = proto_item_add_subtree(remote_cand_item, ett_xmpp_jingle_cont_trans_rem_cand);

    display_attrs(remote_cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));

    xmpp_unknown(remote_cand_tree, tvb, pinfo, element);
}

/*XEP-0177: Jingle Raw UDP Transport Method urn:xmpp:jingle:transports:raw-udp:1*/
static void
xmpp_jingle_cont_trans_raw(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME, "candidate", xmpp_jingle_cont_trans_raw_candidate, MANY}
    };

    trans_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans, tvb, element->offset, element->length, FALSE);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_jingle_cont_trans);

    display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(trans_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_trans_raw_candidate(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    const gchar *type_enums[] = {"host", "prflx", "relay", "srflx"};
    array_t *type_enums_array = ep_init_array_t(type_enums,array_length(type_enums));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"component", -1, TRUE, FALSE, NULL, NULL},
        {"generation", -1, TRUE, FALSE, NULL, NULL},
        {"id", -1, TRUE, FALSE, NULL, NULL},
        {"ip", -1, TRUE, TRUE, NULL, NULL},
        {"port", -1, TRUE, TRUE, NULL, NULL},
        {"type", -1, TRUE, TRUE, val_enum_list, type_enums_array}
    };

    cand_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_cand, tvb, element->offset, element->length, FALSE);
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_jingle_cont_trans_cand);

    display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(cand_tree, element, pinfo, tvb, NULL, 0);
}

/*XEP-0260: Jingle SOCKS5 Bytestreams Transport Method urn:xmpp:jingle:transports:s5b:1*/
static void
xmpp_jingle_cont_trans_s5b(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *trans_item;
    proto_tree *trans_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL},
        {"mode", -1, FALSE, TRUE, NULL, NULL},
        {"sid", -1, FALSE, TRUE, NULL, NULL},
    };

    elem_info elems_info [] = {
        {NAME, "candidate", xmpp_jingle_cont_trans_s5b_candidate, MANY},
        {NAME, "activated", xmpp_jingle_cont_trans_s5b_activated, ONE},
        {NAME, "candidate-used", xmpp_jingle_cont_trans_s5b_cand_used, ONE},
        {NAME, "candidate-error", xmpp_jingle_cont_trans_s5b_cand_error, ONE},
        {NAME, "proxy-error", xmpp_jingle_cont_trans_s5b_proxy_error, ONE},
    };

    trans_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans, tvb, element->offset, element->length, FALSE);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_jingle_cont_trans);

    display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(trans_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_cont_trans_s5b_candidate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *cand_item;
    proto_tree *cand_tree;

    const gchar * type_enums[] = {"assisted", "direct", "proxy", "tunnel"};
    array_t *type_enums_array = ep_init_array_t(type_enums, array_length(type_enums));

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, FALSE, NULL, NULL},
        {"cid", -1, TRUE, TRUE, NULL, NULL},
        {"jid", -1, TRUE, TRUE, NULL, NULL},
        {"port", -1, FALSE, TRUE, NULL, NULL},
        {"priority", -1, TRUE, TRUE, NULL, NULL},
        {"type", -1, TRUE, TRUE, val_enum_list, type_enums_array}
    };

    cand_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_cand, tvb, element->offset, element->length, FALSE);
    cand_tree = proto_item_add_subtree(cand_item, ett_xmpp_jingle_cont_trans_cand);

    display_attrs(cand_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(cand_tree, element, pinfo, tvb, NULL, 0);
}

static void
xmpp_jingle_cont_trans_s5b_activated(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *activated_item;
    attr_t *cid = get_attr(element, "cid");

    activated_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_activated, tvb, element->offset, element->length, FALSE);
    proto_item_append_text(activated_item, " [cid=\"%s\"]",cid?cid->value:"");
    
    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_trans_s5b_cand_used(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *cand_used_item;
    attr_t *cid = get_attr(element, "cid");

    cand_used_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_candidate_used, tvb, element->offset, element->length, FALSE);
    proto_item_append_text(cand_used_item, " [cid=\"%s\"]",cid?cid->value:"");

    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_trans_s5b_cand_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_candidate_error, tvb, element->offset, element->length, FALSE);
    xmpp_unknown(tree, tvb, pinfo, element);
}

static void
xmpp_jingle_cont_trans_s5b_proxy_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans_proxy_error, tvb, element->offset, element->length, FALSE);
    xmpp_unknown(tree, tvb, pinfo, element);
}

/*XEP-0261: Jingle In-Band Bytestreams Transport Method urn:xmpp:jingle:transports:ibb:1*/
static void
xmpp_jingle_cont_trans_ibb(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element) {
    proto_item *trans_item;
    proto_tree *trans_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, FALSE, TRUE, NULL, NULL},
        {"block-size", -1, TRUE, TRUE, NULL, NULL},
        {"sid", -1, TRUE, TRUE, NULL, NULL},
        {"stanza", -1, FALSE, TRUE, NULL, NULL}
    };
    
    trans_item = proto_tree_add_item(tree, hf_xmpp_jingle_cont_trans, tvb, element->offset, element->length, FALSE);
    trans_tree = proto_item_add_subtree(trans_item, ett_xmpp_jingle_cont_trans);

    display_attrs(trans_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(trans_tree, element, pinfo, tvb, NULL, 0);
}

/*XEP-0234: Jingle File Transfer urn:xmpp:jingle:apps:file-transfer:3*/
static void
xmpp_jingle_file_transfer_desc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    elem_info elems_info[] = {
        {NAME, "offer", xmpp_jingle_file_transfer_offer, ONE},
        {NAME, "request", xmpp_jingle_file_transfer_request, ONE}
    };

    desc_item = proto_tree_add_item(tree, hf_xmpp_jingle_content_description, tvb, element->offset, element->length, FALSE);
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_jingle_content_description);

    display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(desc_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_offer(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *offer_item;
    proto_tree *offer_tree;

    elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    offer_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_offer, tvb, element->offset, element->length, FALSE);
    offer_tree = proto_item_add_subtree(offer_item, ett_xmpp_jingle_file_transfer_offer);

    display_attrs(offer_tree, element, pinfo, tvb, NULL, 0);
    display_elems(offer_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_request(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *request_item;
    proto_tree *request_tree;

    elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    request_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_request, tvb, element->offset, element->length, FALSE);
    request_tree = proto_item_add_subtree(request_item, ett_xmpp_jingle_file_transfer_request);

    display_attrs(request_tree, element, pinfo, tvb, NULL, 0);
    display_elems(request_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_received(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *received_item;
    proto_tree *received_tree;

    elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    received_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_received, tvb, element->offset, element->length, FALSE);
    received_tree = proto_item_add_subtree(received_item, ett_xmpp_jingle_file_transfer_received);

    display_attrs(received_tree, element, pinfo, tvb, NULL, 0);
    display_elems(received_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_abort(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *abort_item;
    proto_tree *abort_tree;

    elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    abort_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_abort, tvb, element->offset, element->length, FALSE);
    abort_tree = proto_item_add_subtree(abort_item, ett_xmpp_jingle_file_transfer_abort);

    display_attrs(abort_tree, element, pinfo, tvb, NULL, 0);
    display_elems(abort_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_checksum(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *checksum_item;
    proto_tree *checksum_tree;

    elem_info elems_info[] = {
        {NAME, "file", xmpp_jingle_file_transfer_file, MANY},
    };

    checksum_item = proto_tree_add_item(tree, hf_xmpp_jingle_file_transfer_checksum, tvb, element->offset, element->length, FALSE);
    checksum_tree = proto_item_add_subtree(checksum_item, ett_xmpp_jingle_file_transfer_checksum);

    display_attrs(checksum_tree, element, pinfo, tvb, NULL, 0);
    display_elems(checksum_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jingle_file_transfer_file(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element)
{
    proto_item *file_item;
    proto_tree *file_tree;

    attr_info attrs_info[] = {
        {"name", -1, FALSE, TRUE, NULL, NULL},
        {"size", -1, FALSE, TRUE, NULL, NULL},
        {"date", -1, FALSE, TRUE, NULL, NULL}
    };

    elem_info elems_info[] = {
        {NAME, "hashes", xmpp_hashes, ONE}
    };

    file_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "FILE");
    file_tree = proto_item_add_subtree(file_item, ett_xmpp_jingle_file_transfer_file);

    change_elem_to_attrib("name", "name", element, transform_func_cdata);
    change_elem_to_attrib("size", "size", element, transform_func_cdata);
    change_elem_to_attrib("date", "date", element, transform_func_cdata);

    display_attrs(file_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(file_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

/*XEP-0278: Jingle Relay Nodes http://jabber.org/protocol/jinglenodes*/
void
xmpp_jinglenodes_services(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *services_item;
    proto_tree *services_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL}
    };

    elem_info elems_info[] = {
        {NAME, "relay", xmpp_jinglenodes_relay_stun_tracker, ONE},
        {NAME, "tracker", xmpp_jinglenodes_relay_stun_tracker, ONE},
        {NAME, "stun", xmpp_jinglenodes_relay_stun_tracker, ONE},
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "SERVICES ");

    services_item = proto_tree_add_item(tree, hf_xmpp_services, tvb, element->offset, element->length, FALSE);
    services_tree = proto_item_add_subtree(services_item, ett_xmpp_services);

    display_attrs(services_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(services_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_jinglenodes_relay_stun_tracker(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *relay_item;
    proto_tree *relay_tree;

    attr_info attrs_info[] = {
        {"address", -1, TRUE, TRUE, NULL, NULL},
        {"port", -1, FALSE, TRUE, NULL, NULL},
        {"policy", -1, TRUE, TRUE, NULL, NULL},
        {"protocol", -1, TRUE, TRUE, NULL, NULL},
    };

    relay_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "%s", element->name);
    relay_tree = proto_item_add_subtree(relay_item, ett_xmpp_services_relay);

    display_attrs(relay_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(relay_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_jinglenodes_channel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *channel_item;
    proto_tree *channel_tree;

    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, FALSE, NULL, NULL},
        {"id", -1, FALSE, FALSE, NULL, NULL},
        {"host", -1, FALSE, TRUE, NULL, NULL},
        {"localport", -1, FALSE, TRUE, NULL, NULL},
        {"remoteport", -1, FALSE, TRUE, NULL, NULL},
        {"protocol", -1, TRUE, TRUE, NULL, NULL},
        {"maxkbps", -1, FALSE, FALSE, NULL, NULL},
        {"expire", -1, FALSE, FALSE, NULL, NULL},
    };

    channel_item = proto_tree_add_item(tree, hf_xmpp_channel, tvb, element->offset, element->length, FALSE);
    channel_tree = proto_item_add_subtree(channel_item, ett_xmpp_channel);

    display_attrs(channel_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(channel_tree, element, pinfo, tvb, NULL, 0);
}
