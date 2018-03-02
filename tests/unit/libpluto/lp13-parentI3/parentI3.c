#include "../lp13-parentI3/parentI3_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_kernel.c"
#include "seam_ikealg.c"

#define TESTNAME "parentI3"

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
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;
    }

    run_continuation(crypto_req);
}

void recv_pcap_packet2(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;

    run_continuation(crypto_req);

}

static void init_loaded(void)
{   /* nothing */ }

#define FINISH_NEGOTIATION
static void finish_negotiation(void)
{
    struct state *st;
    st = state_with_serialno(1);
    passert(st != NULL);

    passert(st->st_oakley.integ_hash == IKEv2_AUTH_HMAC_SHA2_256_128);
    passert(st->st_oakley.prf_hash   == IKEv2_PRF_HMAC_SHA2_256);
    passert(st->st_oakley.encrypt    == IKEv2_ENCR_AES_CBC);
    passert(st->st_oakley.enckeylen  == 128);

    st = state_with_serialno(2);
    passert(st != NULL);

    passert(st->st_esp.present);
    passert(st->st_esp.attrs.transattrs.integ_hash == IKEv2_AUTH_HMAC_SHA2_256_128);
    passert(st->st_esp.attrs.transattrs.encrypt    == IKEv2_ENCR_AES_CBC);
    passert(st->st_esp.attrs.transattrs.enckeylen  == 128);
}


#include "../lp13-parentI3/parentI3_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
