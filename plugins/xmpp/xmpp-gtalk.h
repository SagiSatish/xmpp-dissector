#ifndef XMPP_GTALK_H
#define	XMPP_GTALK_H

extern void xmpp_gtalk_session(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_jingleinfo_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_usersetting(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_nosave_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_nosave_x(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_mail_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_mail_mailbox(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_mail_new_mail(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_status_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
#endif	/* XMPP_GTALK_H */

