: ==== start ====
TESTNAME=basic-pluto-04
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-aes128
/testing/pluto/bin/wait-for-pluto-started
