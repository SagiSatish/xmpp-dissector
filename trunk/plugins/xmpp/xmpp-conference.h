#ifndef XMPP_CONFERENCE_H
#define	XMPP_CONFERENCE_H

extern void xmpp_conferece_info_advert(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);
extern void xmpp_conference_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *element);

#endif	/* XMPP_CONFERENCE_H */

