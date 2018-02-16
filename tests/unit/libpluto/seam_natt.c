#ifndef __seam_natt_c__
#define __seam_natt_c__
#include "pluto/nat_traversal.h"
#include "pluto/vendor.h"
bool nat_traversal_support_non_ike;
bool nat_traversal_support_port_floating;
bool nat_traversal_enabled;
void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st)
{}
void nat_traversal_ka_event (void) {}

bool nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
                            struct msg_digest *md) { return TRUE; }

void nat_traversal_natd_lookup(struct msg_digest *md) {}
void nat_traversal_show_result (u_int32_t nt, u_int16_t sport) {}
u_int32_t nat_traversal_vid_to_method(unsigned short nat_t_vid) { return LELEM(NAT_TRAVERSAL_RFC); }

void nat_traversal_new_ka_event (void) {}

void init_nat_traversal (bool activate, unsigned int keep_alive_period,
                         bool fka, bool spf) {}

#endif
