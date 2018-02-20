#ifndef __seam_fakevendor_c__
#define __seam_fakevendor_c__
#ifndef PLUTO_VENDORID_SIZE
#define PLUTO_VENDORID_SIZE 12
#endif

/*
 - ipsec_version_code - return IPsec version number/code, as string
 */
const char *ipsec_version_code() {   return "2.6-regression"; }

/*
 - ipsec_version_string - return full version string
 */
const char *ipsec_version_string(){  return "Openswan 2.6-regression"; }



#endif
