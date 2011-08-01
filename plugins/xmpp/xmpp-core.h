#ifndef XMPP_CORE_H
#define	XMPP_CORE_H

extern void xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, element_t *packet, gint hf, gint ett, const char *col_info);
extern void xmpp_failure(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_xml_header(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_stream(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern gboolean xmpp_stream_close(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo);
#endif	/* XMPP_CORE_H */

