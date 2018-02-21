#define INCLUDE_IKEV1_PROCESSING
#define OMIT_MAIN_MODE
#define NAPT_ENABLED 1
#define NAT_TRAVERSAL
#define SEAM_CRYPTO
#include "../lp12-parentR2/parentR2_head.c"
#include "nat_traversal.h"
#include "seam_dpd.c"
#include "seam_ikev1_aggr.c"
#include "seam_ikev1_phase2.c"
#include "seam_unpend.c"
#include "seam_command.c"
#include "seam_kernel.c"
#include "seam_ikealg.c"
#include "seam_crypt.c"
#include "seam_x509.c"
#include "seam_rsasig.c"
#include "seam_gr_sha1_group14.c"
#include "seam_host_jamesjohnson.c"

#define TESTNAME "parentN2"

bool no_cr_send = TRUE;

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

#include "seam_parentR2.c"
#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
