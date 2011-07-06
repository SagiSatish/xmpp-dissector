#ifndef XMPP_GTALK_H
#define	XMPP_GTALK_H

extern void xmpp_gtalk_session(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_jingleinfo_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);

#endif	/* XMPP_GTALK_H */

