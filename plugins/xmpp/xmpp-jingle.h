#ifndef XMPP_JINGLE_H
#define	XMPP_JINGLE_H

extern void xmpp_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
extern void xmpp_jinglenodes_services(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
extern void xmpp_jinglenodes_channel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

#endif	/* XMPP_JINGLE_H */

