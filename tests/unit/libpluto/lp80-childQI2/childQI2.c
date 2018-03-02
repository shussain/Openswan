#define INCLUDE_IKEV1_PROCESSING
#define INCLUDE_QUICK_MODE
#define OMIT_MAIN_MODE
#define NAPT_ENABLED 1
#define NAT_TRAVERSAL
#define SEAM_CRYPTO
#include "../lp10-parentI2/parentI2_head.c"
#include "nat_traversal.h"
#include "seam_rsasig.c"
#include "seam_x509.c"
#include "seam_dpd.c"
#include "seam_command.c"
#include "seam_ikev1_crypto.c"
#include "seam_nonce.c"
#include "seam_rsa_check.c"
#include "seam_host_parker.c"

#define TESTNAME "childQI2"

bool no_cr_send = 0;

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
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

static void init_loaded(void) {}

/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE|DBG_NATT;
        st->hidden_variables.st_nat_traversal |= NAT_T_WITH_NATD;

        clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc14_ni, tc14_ni_len);
        clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc14_gi, tc14_gi_len);
        clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc14_secretr,tc14_secretr_len);
    }

    run_continuation(crypto_req);
}

#ifndef PCAP_INPUT_COUNT
#define PCAP_INPUT_COUNT 4
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_packet,
    recv_pcap_packet,
    recv_pcap_packet,
};
#endif

#define FINISH_NEGOTIATION
static void finish_negotiation(void)
{
    volatile struct state *st;
    st = state_with_serialno(1);
    passert(st != NULL);

    passert(st->st_oakley.integ_hash == IKEv2_AUTH_HMAC_SHA1_96);
    passert(st->st_oakley.prf_hash   == IKEv2_AUTH_HMAC_SHA1_96);
    passert(st->st_oakley.encrypt    == IKEv2_ENCR_AES_CBC);
    passert(st->st_oakley.enckeylen  == 128);

    st = state_with_serialno(2);
    passert(st != NULL);

    passert(st->st_esp.present);
    passert(st->st_esp.attrs.transattrs.integ_hash == IKEv2_AUTH_HMAC_SHA1_96);
    passert(st->st_esp.attrs.transattrs.encrypt    == IKEv2_ENCR_AES_CBC);
    passert(st->st_esp.attrs.transattrs.enckeylen  == 128);
}


#include "../lp10-parentI2/parentI2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
