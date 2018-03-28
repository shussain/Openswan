#define INCLUDE_IKEV1_PROCESSING
#define OMIT_MAIN_MODE
#define NAT_TRAVERSAL
#define SEAM_CRYPTO
#include "../lp12-parentR2/parentR2_head.c"
#include "seam_ikev1.c"
#include "seam_ikev1_aggr.c"
#include "seam_pending.c"
#include "nat_traversal.h"
#include "seam_dpd.c"
#include "seam_ikev1_phase2.c"
#include "seam_unpend.c"
#include "seam_command.c"
#include "seam_kernel.c"
#include "seam_ikealg.c"
#include "seam_crypt.c"
#include "seam_rsasig.c"
#include "seam_rsa_check.c"
#include "seam_host_moon.c"

#define TESTNAME "v1certN3"

bool no_cr_send = TRUE;
long crl_check_interval = 0;

static void init_local_interface(void)
{
    nat_traversal_support_non_ike = TRUE;
    nat_traversal_support_port_floating = TRUE;
    nat_traversal_enabled = TRUE;
    init_moon_interface(TRUE);
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));

    osw_init_ipsecdir("../samples/moon");
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/moon.secrets"
			       , &pass, NULL);
}

static void init_loaded(void)
{   /* nothing */ }


#define PCAP_INPUT_COUNT 3

#include "seam_gi_sha1.c"

static void update_ngi_tc3(struct pcr_kenonce *kn)
{
    if(kn->thespace.len == 0) {
        fprintf(stderr, "failed to setup crypto_req, exiting\n");
        exit(89);
    }

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc3_nr, tc3_nr_len);
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc3_gr, tc3_gr_len);
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc3_secret, tc3_secret_len);
}

void recv_pcap_packet1ikev1(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st) {
      st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    }
}

void recv_pcap_packet2ikev1_128(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    passert(st->st_suspended_md != NULL);

    /* find st involved */
    st = state_with_serialno(1);
    if(st) {
      st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
      update_ngi_tc3(kn);
      run_one_continuation(crypto_req);
    }

    passert(st->st_suspended_md == NULL);
}

recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet1ikev1,
    recv_pcap_packet2ikev1_128,
    recv_pcap_packet1ikev1,
};

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */