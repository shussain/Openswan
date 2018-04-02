#include "../lp10-parentI2/parentI2_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_kernel.c"
#include "ikev2sendI1.c"
#include "seam_keys2.c"
#include "seam_pending.c"
#include "seam_ke.c"
#include "seam_dh_v2.c"
#include "seam_x509.c"
#include "seam_natt.c"
#include "seam_host_parker.c"

#define TESTNAME "cryptoI2"

static void init_local_interface(void)
{
    nat_traversal_support_non_ike = TRUE;
    nat_traversal_support_port_floating = TRUE;
    nat_traversal_enabled = TRUE;
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "/parker.secrets"
			       , NULL, NULL);
}

static void init_loaded(void) {}

void delete_cryptographic_continuation(struct state *st) {}

void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;

    recv_pcap_packet_gen(user, h, bytes);

    st = state_with_serialno(1);
    if(st) {
        st->st_connection->extra_debugging = DBG_CRYPT|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;
    }
    run_continuation(crypto_req);
}

#ifndef PCAP_INPUT_COUNT
#define PCAP_INPUT_COUNT 1
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
};
#endif


#include "../lp10-parentI2/parentI2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
