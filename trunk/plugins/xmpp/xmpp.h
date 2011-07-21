#ifndef _XMPP_H_
#define _XMPP_H_

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

#define elem_cdata(elem) \
elem->data?elem->data->value:""

typedef struct _array_t
{
    gpointer data;
    gint length;
} array_t;

typedef struct _attr_t{
    gchar *value;
    gchar *name;
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
    
    /*abbreviation that apprears before tag name (<nos:x .../>)
     if abbrev doesn't appear then NULL*/
    gchar* default_ns_abbrev; 

    GHashTable *attrs;
    GList *elements;
    data_t *data;
    proto_item *item;

    gint offset;
    gint length;

    gboolean was_read;
} element_t;

/*informations about attributes that are displayed in proto tree*/
typedef struct _attr_info{
    gchar *name;
    gint hf;
    gboolean is_required;
    gboolean in_short_list;

    /*function validates this attribute
    it may impose other restrictions (e.g. validating atribut's name, ...)*/
    void (*val_func)(packet_info *pinfo, proto_item *item, gchar *name, gchar *value, gpointer data);
    gpointer data;
} attr_info;

typedef enum _elem_info_type{
    NAME,
    ATTR,
    NAME_AND_ATTR,
    NAMES
} elem_info_type;

typedef enum _elem_info_occurrence
{
    ONE,MANY
} elem_info_occurrence;

/*informations about elements that are displayed in proto tree*/
typedef struct _elem_info{
    elem_info_type type;
    gpointer data;
    /*function that displays element in tree*/
    void (*elem_func)(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
    elem_info_occurrence occurrence;
} elem_info;

typedef struct _xmpp_conv_info_t {
    emem_tree_t *req_resp;
    emem_tree_t *jingle_sessions;
    emem_tree_t *ibb_sessions;
    emem_tree_t *gtalk_sessions;
} xmpp_conv_info_t;

typedef struct _xmpp_reqresp_transaction_t {
    guint32 req_frame;
    guint32 resp_frame;
} xmpp_transaction_t;

extern void xmpp_iq_reqresp_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);
extern void xmpp_jingle_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);
extern void xmpp_ibb_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);
extern void xmpp_gtalk_session_track(packet_info *pinfo, element_t *packet, xmpp_conv_info_t *xmpp_info);
extern void xmpp_unknown(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

extern element_t* xml_frame_to_element_t(xml_frame_t *xml_frame, gboolean first);
extern void element_t_tree_free(element_t *root);

extern array_t* ep_init_array_t(const gchar** array, gint len);
extern attr_t* ep_init_attr_t(gchar *value, gint offset, gint length);
extern gchar* ep_string_upcase(const gchar* string);

extern gint element_t_cmp(gconstpointer a, gconstpointer b);
extern GList* find_element_by_name(element_t *packet,const gchar *name);
extern element_t* steal_element_by_name(element_t *packet, const gchar *name);
extern element_t* steal_element_by_names(element_t *packet, const gchar **names, gint names_len);
extern element_t* steal_element_by_attr(element_t *packet, const gchar *attr_name, const gchar *attr_value);
extern element_t* steal_element_by_name_and_attr(element_t *packet, const gchar *name, const gchar *attr_name, const gchar *attr_value);
extern element_t* get_first_element(element_t *packet);

extern gchar* element_to_string(tvbuff_t *tvb, element_t *element);
extern gchar* attr_to_string(tvbuff_t *tvb, attr_t *attr);

extern attr_t* get_attr(element_t *element, const gchar* attr_name);

extern void proto_tree_hide_first_child(proto_tree *tree);
extern void proto_tree_show_first_child(proto_tree *tree);
extern gchar* proto_item_get_text(proto_item *item);

extern gpointer name_attr_struct(gchar *name, gchar *attr_name, gchar *attr_value);

extern void display_attrs(proto_tree *tree, element_t *element, packet_info *pinfo, tvbuff_t *tvb, attr_info *attrs, guint n);
extern void display_elems(proto_tree *tree, element_t *parent, packet_info *pinfo, tvbuff_t *tvb, elem_info *elems, guint n);

extern void val_enum_list(packet_info *pinfo, proto_item *item, gchar *name, gchar *value, gpointer data);

extern void change_elem_to_attrib(const gchar *elem_name, const gchar *attr_name, element_t *parent, attr_t* (*transform_func)(element_t *element));
extern attr_t* transform_func_cdata(element_t *elem);

#endif

