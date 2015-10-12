# Introduction #

This file is HOWTO for XMPP dissector developers. Before reading this doc you should be familiar with Wireshark README files, especialy README.developer and README.plugins.

## How XMPP dissector displays packets ##

Packet that looks like:
```
<iq
    from='marok.test@gmail.com/gmail.9EB5BC18'
    to='marok@marook.dyndns.org/c92ed70a'
    type='set'
    id='90E8492345BCC05E'>
    <jin:jingle
        action='session-initiate'
        sid='c1448747008' initiator='marok.test@gmail.com/gmail.9EB5BC18'
        xmlns:jin='urn:xmpp:jingle:1'>
        <jin:content
            name='video'
            creator='initiator'>
            <rtp:description media='video' xmlns:rtp='urn:xmpp:jingle:apps:rtp:1'>
                <rtp:payload-type id='99' name='H264-SVC'>
                    ...
                </rtp:payload-type>              
            </rtp:description>
            <p:transport xmlns:p='http://www.google.com/transport/p2p'/>
        </jin:content>
    </jin:jingle>
</iq>
```
is displayed by Wireshark like in the screenshoot:

![http://dl.dropbox.com/u/4436801/wireshark_xmpp/ws_zrzut.png](http://dl.dropbox.com/u/4436801/wireshark_xmpp/ws_zrzut.png)

Areas marked in the picture above means:
  1. element name - jingle
  1. namespace abbreviation - jin
  1. important arguments
  1. all arguments

# Files structure #

XMPP dissector is written as a plugin. Hence all files related to this dissector are stored in plugins/xmpp directory.

Files and their content:
  * packet-xmpp.c _(main file of the XMPP dissector)_
    * header fields (hf`_``*`) and subtree ids (ett`_``*`) initializations
    * XMPP\_PORT
    * dissect\_xmpp, proto\_reg\_handoff\_xmpp, proto\_register\_xmpp - characteristic functions for each dissector
  * packet-xmpp.h
    * header fields (hf`_``*`) and subtree ids (ett`_``*`) exports
    * ETT\_UNKNOWN\_LEN - it describes depth of tree for unknown elements. If depth of tree for unknown element is higher than ETT\_UNKNOWN\_LEN then packet is set as malformed. In this case it should be increased.
  * xmpp-utils.c
    * functions responsible for: getting data from XML dissector, displaying them into protocol tree, managing memory
  * xmpp-`*`.c
    * functions that process specific elements

# Adding custom type of packet #

## Skeleton code ##

Each function that processes the part of XMPP packet should return void and have 4 parameters: proto\_tree, tvbuff\_t, packet\_info and element\_t.
```
void xmpp_foo(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element)
```

Standard proto`_`tree and proto`_`item declaration.
```
proto_item *foo_item;
proto_tree *foo_tree;
```

Below we can see declaration of attributes and elements which will be searched in _element_.
_attr\_info_ structure consists of attribute name, header field, boolean value describing that the attribute is required, another bool making that the attribute is displayed in area no. 3 (important attributes), pointer to the validation function and pointer to the data passing to this function.
_elem\_info_ structure consists of a way of searching an element, data required to looking for an element, function that will process found element, number of possible occurences of an element.
```
attr_info attrs_info[] = {
    {"attr1", hf_xmpp_foo_attr, TRUE, TRUE, NULL, NULL},
    {"attr2", -1, FALSE, TRUE, NULL, NULL},
};
elem_info elems_info[] = {
    {NAME, "bar", xmpp_foo_bar, MANY},
};
```

Standard proto`_`tree and proto`_`item initialization.
```
foo_item = proto_tree_add_item(tree, hf_xmpp_foo, tvb, element->offset, element->length, TRUE);
foo_tree = proto_item_add_subtree(foo_item,ett_xmpp_foo);
```

Calling functions that display attributes and elements in tree using _attr\_info_ array and _elem\_info_ array. If _display\_elems_ doesn't call then function _xmpp\_unknown_ MUST be called.
```
display_attrs(foo_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
display_elems(foo_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
```
## Example ##
Let's take an example of the [roster packet](http://xmpp.org/schemas/roster.xsd).

ROSTER packet consist of one element _QUERY_ and _QUERY_ has only one child _ITEM_.

At first you should add proper header fields and subtree IDs to the _packet-xmpp.c_
```
gint hf_xmpp_query = -1;
gint hf_xmpp_query_item = -1;

gint ett_xmpp_query = -1;
gint ett_xmpp_query_item = -1;
```
and put them into right array.
```
static hf_register_info hf[] = {
        ...
        { &hf_xmpp_query,
        {
            "QUERY", "xmpp.query", FT_NONE, BASE_NONE, NULL, 0x0,
            "iq query", HFILL
        }},
        { &hf_xmpp_query_item,
        {
            "ITEM", "xmpp.query.item", FT_NONE, BASE_NONE, NULL, 0x0,
            "iq query item", HFILL

        }},
        ...
}

static gint * ett[] = {
        &ett_xmpp,
        &ett_xmpp_iq,
        &ett_xmpp_query,
        &ett_xmpp_query_item,
        ...
};
```
These variables have to be visible in files that contain our dissection functions (e.g. in the _xmpp-other.c_), so you should add them to the _packet-xmpp.h_.
```
extern gint hf_xmpp_query;
extern gint hf_xmpp_query_item;

extern gint ett_xmpp_query;
extern gint ett_xmpp_query_item;
```


```
xmpp_roster_query(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *query_item;
    proto_tree *query_tree;
```
_QUERY_ element may have only 2 attributes: _xmlns_ and _ver_. _hf\_xmpp\_xmlns_ is header field that is added to each _xmlns_ attribute that occurs. _ver_ attribute is displayed as text (-1 instead of header field).
```
    attr_info attrs_info[] = {
        {"xmlns", hf_xmpp_xmlns, TRUE, TRUE, NULL, NULL},
        {"ver", -1, FALSE, TRUE, NULL, NULL},
    };
```
_QUERY_ may also contain many _ITEM_ elements.
```
    elem_info elems_info[] = {
        {NAME, "item", xmpp_roster_item, MANY},
    };
```
Information about sort of packet is set in column info field. It facilitates the analisis of captured packets.
```

    col_append_fstr(pinfo->cinfo, COL_INFO, "QUERY(jabber:iq:roster) ");
```
Standard proto`_`tree and proto`_`item initialization. Header field and subtree ID are added to the protocol tree.
```
    query_item = proto_tree_add_item(tree, hf_xmpp_query, tvb, element->offset, element->length, FALSE);
    query_tree = proto_item_add_subtree(query_item, ett_xmpp_query);
```
Information are displayed in the protocol tree using _attrs`_`info_ and _elems`_`info_. Attributes and elements, that aren't defined in these structures, are displayed as text.
```
    display_attrs(query_tree, element, pinfo, tvb, attrs_info, array_length(attrs_info));
    display_elems(query_tree, element, pinfo, tvb, elems_info, array_length(elems_info));
```

```
}
```
Now, let's write function that dissect _ITEM_ that is part of _QUERY_. This function may be static, because it is called only by _xmpp`_`roster`_`query_.
```
static void
xmpp_roster_item(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, element_t *element)
{
    proto_item *item_item;
    proto_tree *item_tree;
```
Declaration and initialization arrays that will validate attributes values. If attribute has value that isn't defined in these arrays then information about it is added to the expert info module.
```
    const gchar *ask_enums[] = {"subscribe"};
    const gchar *subscription_enums[] = {"both","from","none","remove","to"};

    array_t *ask_enums_array = ep_init_array_t(ask_enums,array_length(ask_enums));
    array_t *subscription_array = ep_init_array_t(subscription_enums,array_length(subscription_enums));
```
If we want to validate some attribute, we must put _val`_`enum`_`list_  and proper _array`_`t_ struct in _attr`_`info_ array.
```
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
```
We can recognize elements manualy as you see below. Otherwise you would have to write another function, create elem\_info array and call the _display`_`elems_.
```
    while((group = steal_element_by_name(element,"group"))!=NULL)
    {
        proto_tree_add_string(item_tree, hf_xmpp_query_item_group, tvb, group->offset, group->length, elem_cdata(group));
    }
```
In this case we MUST call _xmpp`_`unknown_, because _display`_`elems_ isn't used.
```
    xmpp_unknown(item_tree, tvb, pinfo, element);
}
```
The last thing that must be done is adding information to the _xmpp`_`iq_ function(_xmpp-core.c_) to the _elems`_`info_ array.
```
void
xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet)
{
    ...
    elem_info elems_info [] = {
        ...
        {NAME_AND_ATTR, name_attr_struct("query", "xmlns", "jabber:iq:roster"), xmpp_roster_query, ONE},
        ...
    };
```