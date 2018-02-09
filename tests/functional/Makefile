# Makefile for the Openswan in-tree test cases
# Copyright (C) 2014 Michael Richardson <mcr@xelerance.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/functional

include ${OPENSWANSRCDIR}/Makefile.inc

FUNCTEST=
FUNCTEST+=01-confread
FUNCTEST+=03-plutostart
FUNCTEST+=04-whackwrite
FUNCTEST+=05-addconn
FUNCTEST+=06-dnsdelay
FUNCTEST+=06-alsoflip
FUNCTEST+=07-sourceipv6
FUNCTEST+=08-sitelocalv6
FUNCTEST+=09-v6inv4
FUNCTEST+=10-defaultroute
FUNCTEST+=11-subnets
FUNCTEST+=12-rwcertwrite
FUNCTEST+=13-bigpubkey

clean check pcapupdate programs:
	@set -e; for test in ${FUNCTEST}; do ${MAKE} -C $$test $@; done

testlist:
	@echo ${FUNCTEST}

