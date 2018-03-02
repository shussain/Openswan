#include "../lp12-parentR2/parentR2_head.c"
#include "seam_pending.c"
#include "seam_kernel.c"
#include "seam_ikev1.c"
#include "seam_ikev1_aggr.c"
#include "seam_ikealg.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_crypt.c"
#include "seam_rsasig.c"
#include "seam_natt.c"

#define TESTNAME "parentR2"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/jj.secrets"
			       , NULL, NULL);
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


#include "seam_parentR2.c"
#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
