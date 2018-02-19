#define INCLUDE_IKEV1_PROCESSING
#define OMIT_MAIN_MODE
#define NAPT_ENABLED 1
#define SEAM_CRYPTO
#include "../lp10-parentI2/parentI2_head.c"
#include "seam_rsasig.c"
#include "seam_keys.c"
#include "seam_x509.c"
#include "seam_dpd.c"
#include "seam_ikev1_aggr.c"
#include "seam_ikev1_phase2.c"
#include "seam_unpend.c"
#include "seam_command.c"
#include "seam_rsa_check.c"
#include "seam_host_parker.c"

#define TESTNAME "parentM2"

bool no_cr_send = 0;

static void init_local_interface(void)
{
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

#include "seam_parentI2.c"
#include "../lp10-parentI2/parentI2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
