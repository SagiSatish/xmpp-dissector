/* xmpp-conference.c
 * Wireshark's XMPP dissector.
 *
 * XEP-0298: Delivering Conference Information to Jingle Participants (Coin)
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[AT]gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include <plugins/xmpp/xmpp-utils.h>
#include <plugins/xmpp/xmpp-conference.h>


static void xmpp_conf_desc(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_conf_state(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_conf_users(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_conf_user(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_conf_endpoint(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
static void xmpp_conf_media(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

void
xmpp_conferece_info_advert(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *cinfo_item;
    proto_tree *cinfo_tree;

    attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"isfocus", -1, TRUE, TRUE, NULL, NULL}
    };

    cinfo_item = proto_tree_add_item(tree, hf_xmpp_conf_info, tvb, element->offset, element->length, FALSE);
    cinfo_tree = proto_item_add_subtree(cinfo_item, ett_xmpp_conf_info);

    display_attrs(cinfo_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(cinfo_tree, element, pinfo, tvb, NULL, 0);
}

void
xmpp_conference_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *cinfo_item;
    proto_tree *cinfo_tree;

    const gchar *state_enums[] = {"full", "partial", "deleted"};
    array_t *state_array = ep_init_array_t(state_enums, array_length(state_enums));

    attr_info attrs_info [] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"entity", -1, TRUE, TRUE, NULL, NULL},
        {"state", -1, FALSE, TRUE, val_enum_list, state_array},
        {"version", -1, FALSE, TRUE, NULL, NULL},
        {"sid", hf_xmpp_conf_info_sid, FALSE, TRUE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME, "conference-description", xmpp_conf_desc, ONE},
        {NAME, "conference-state", xmpp_conf_state, ONE},
        /*{NAME, "host-info", xmpp_conf_host_info, ONE},*/
        {NAME, "users", xmpp_conf_users, ONE},
        /*{NAME, "sidebars-by-ref", xmpp_conf_sidebars_by_ref, ONE},*/
        /*{NAME, "sidebars-by-val", xmpp_conf_sidebars_by_val, ONE},*/
    };

    col_append_fstr(pinfo->cinfo, COL_INFO, "CONFERENC-INFO ");

    cinfo_item = proto_tree_add_item(tree, hf_xmpp_conf_info, tvb, element->offset, element->length, FALSE);
    cinfo_tree = proto_item_add_subtree(cinfo_item, ett_xmpp_conf_info);

    display_attrs(cinfo_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(cinfo_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_conf_desc(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *desc_item;
    proto_tree *desc_tree;

    attr_info attrs_info [] = {
        {"subject", -1, FALSE, TRUE, NULL, NULL},
        {"display-text", -1, FALSE, FALSE, NULL, NULL},
        {"free-text", -1, FALSE, FALSE, NULL, NULL},
        {"max-user-count", -1, FALSE, FALSE, NULL, NULL},
    };

/*
    elem_info elems_info [] = {
        {NAME, "keywords", xmpp_conf_desc_keywords, ONE},
        {NAME, "conf-uris", xmpp_conf_desc_conf_uris, ONE},
        {NAME, "service-uris", xmpp_conf_desc_serv_uris, ONE},
        {NAME, "available-media", xmpp_conf_desc_avil_media, ONE},
    };
*/

    desc_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "CONFERENCE DESCRIPTION");
    desc_tree = proto_item_add_subtree(desc_item, ett_xmpp_conf_desc);

    change_elem_to_attrib("subject", "subject", element, transform_func_cdata);
    change_elem_to_attrib("display-text", "display-text", element, transform_func_cdata);
    change_elem_to_attrib("free-text", "free-text", element, transform_func_cdata);
    change_elem_to_attrib("maximum-user-count", "max-user-count", element, transform_func_cdata);

    display_attrs(desc_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(desc_tree, element, pinfo, tvb, NULL,0);
}

static void
xmpp_conf_state(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *state_item;
    proto_tree *state_tree;

    attr_info attrs_info [] = {
        {"user-count", -1, FALSE, TRUE, NULL, NULL},
        {"active", -1, FALSE, TRUE, NULL, NULL},
        {"locked", -1, FALSE, TRUE, NULL, NULL}
    };

    state_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "CONFERENCE STATE");
    state_tree = proto_item_add_subtree(state_item, ett_xmpp_conf_state);

    change_elem_to_attrib("user-count", "user-count", element, transform_func_cdata);
    change_elem_to_attrib("active", "active", element, transform_func_cdata);
    change_elem_to_attrib("locked", "locked", element, transform_func_cdata);

    display_attrs(state_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(state_tree, element, pinfo, tvb, NULL,0);
    
}

static void
xmpp_conf_users(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *users_item;
    proto_tree *users_tree;

    attr_info attrs_info [] = {
        {"state", -1, FALSE, TRUE, NULL, NULL}
    };

    elem_info elems_info [] = {
        {NAME, "user", xmpp_conf_user, MANY}
    };

    users_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "USERS");
    users_tree = proto_item_add_subtree(users_item, ett_xmpp_conf_users);   

    display_attrs(users_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(users_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}
static void
xmpp_conf_user(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *user_item;
    proto_tree *user_tree;

    attr_info attrs_info [] = {
        {"entity", -1, FALSE, TRUE, NULL, NULL},
        {"state", -1, FALSE, TRUE, NULL, NULL},
        {"display-text", -1, FALSE, TRUE, NULL, NULL},
        {"cascaded-focus", -1, FALSE, TRUE, NULL, NULL}
    };

    elem_info elems_info [] = {
        /*{NAME, "associated-aors", xmpp_conf_assoc_aors, ONE},*/
        /*{NAME, "roles", xmpp_conf_roles, ONE},*/
        /*{NAME, "languages", xmpp_conf_langs, ONE},*/
        {NAME, "endpoint", xmpp_conf_endpoint, MANY},
    };

    user_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "USERS");
    user_tree = proto_item_add_subtree(user_item, ett_xmpp_conf_user);

    change_elem_to_attrib("display-text", "display-text", element, transform_func_cdata);
    change_elem_to_attrib("cascaded-focus", "cascaded-focus", element, transform_func_cdata);

    display_attrs(user_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(user_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_conf_endpoint(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *endpoint_item;
    proto_tree *endpoint_tree;

    attr_info attrs_info [] = {
        {"entity", -1, FALSE, TRUE, NULL, NULL},
        {"state", -1, FALSE, TRUE, NULL, NULL},
        {"display-text", -1, FALSE, TRUE, NULL, NULL},
        {"status", -1, FALSE, TRUE, NULL, NULL},
        {"joining-method", -1, FALSE, TRUE, NULL, NULL},
        {"disconnection-method", -1, FALSE, TRUE, NULL, NULL},
    };

    elem_info elems_info [] = {
        /*{NAME,"referred",...,ONE},*/
        /*{NAME,"joining-info",...,ONE},*/
        /*{NAME,"disconnection-info",...,ONE},*/
        {NAME,"media", xmpp_conf_media, ONE},
        /*{NAME,"call-info",...,ONE},*/

    };

    endpoint_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "ENDPOINT");
    endpoint_tree = proto_item_add_subtree(endpoint_item, ett_xmpp_conf_endpoint);

    change_elem_to_attrib("display-text", "display-text", element, transform_func_cdata);
    change_elem_to_attrib("status", "status", element, transform_func_cdata);
    change_elem_to_attrib("joining-method", "joining-method", element, transform_func_cdata);
    change_elem_to_attrib("disconnection-method", "disconnection-method", element, transform_func_cdata);


    display_attrs(endpoint_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(endpoint_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
}

static void
xmpp_conf_media(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
{
    proto_item *media_item;
    proto_tree *media_tree;

    attr_info attrs_info[] = {
        {"id", -1, TRUE, TRUE, NULL, NULL},
        {"display-text", -1, FALSE, TRUE, NULL, NULL},
        {"type", -1, FALSE, TRUE, NULL, NULL},
        {"label", -1, FALSE, TRUE, NULL, NULL},
        {"src-id", -1, FALSE, TRUE, NULL, NULL},
        {"status", -1, FALSE, TRUE, NULL, NULL},
    };

    media_item = proto_tree_add_text(tree, tvb, element->offset, element->length, "MEDIA");
    media_tree = proto_item_add_subtree(media_item, ett_xmpp_conf_media);

    change_elem_to_attrib("display-text", "display-text", element, transform_func_cdata);
    change_elem_to_attrib("type", "type", element, transform_func_cdata);
    change_elem_to_attrib("label", "label", element, transform_func_cdata);
    change_elem_to_attrib("src-id", "src-id", element, transform_func_cdata);
    change_elem_to_attrib("status", "status", element, transform_func_cdata);

    display_attrs(media_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(media_tree, element, pinfo, tvb, NULL, 0);
}