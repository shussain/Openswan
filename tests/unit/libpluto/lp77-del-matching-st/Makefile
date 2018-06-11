# FreeS/WAN testing makefile
# Copyright (C) 2015 Michael Richardson <mcr@xelerance.com>
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

OPENSWANSRCDIR?=$(shell cd ../../../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/unit/libpluto/lp77-del-matching-st
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE} -I..
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG}

include ../Makefile.typical-seam-list

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
SAMPLEDIR=../samples
OUTPUTS=OUTPUT

include Makefile.testcase

EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

Q=$(if ${V},,@)
programs ${TESTNAME}: ${TESTNAME}.c ${EXTRAOBJS} ../seam_*.c
	@echo "file ${TESTNAME}"          >.gdbinit
	@echo "set args "${UNITTESTARGS} >>.gdbinit
	@echo " CC ${TESTNAME}"
	${Q}${CC} -c -g -O0 ${TESTNAME}.c ${EXTRAFLAGS}
	@echo " LD ${TESTNAME}"
	${Q}${CC} -g -O0 -o ${TESTNAME} ${TESTNAME}.o ${EXTRAFLAGS} ${EXTRAOBJS} ${EXTRALIBS}

check:	OUTPUT ${EXTRAOBJS} ${TESTNAME}
	ulimit -c unlimited && ./${TESTNAME} ${UNITTESTARGS} >OUTPUT/${TESTNAME}.txt 2>&1
	@sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}.txt | diff - output.txt

${TESTNAME}.E:
	@${CC} -E -c -g -o ${TESTNAME}.E -O0 ${TESTNAME}.c ${EXTRAFLAGS}

update: OUTPUT
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}.txt >output.txt

clean: OUTPUT
	rm -f OUTPUT/${TESTNAME}.txt ${TESTNAME} ${WHACKFILE} OUTPUT/${TESTNAME}.pcap *.o *~

OUTPUT:
	@mkdir -p OUTPUT

# Local Variables:
# compile-command: "make check"
# End:
#
