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

OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/functional/01-confread

include ${OPENSWANSRCDIR}/Makefile.inc

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
OUTPUTS=OUTPUTS
SAMPLEDIR=../01-confread
SAMPLE2DIR=../../unit/libpluto/samples

TEST3ARGS=--rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord2.whack --all
TEST4ARGS=--rootdir=${SAMPLE2DIR}/h2h --config ${SAMPLE2DIR}/h2h.conf --whackout=${OUTPUTS}/h2h.whack --debug --all
TEST6ARGS=--rootdir=${SAMPLE2DIR}/carol --config c2-missing-trailing-newline.conf --whackout=${OUTPUTS}/c2-missing-trailing-newline.whack --all

export EF_DISABLE_BANNER=1

# note may fail if core dumps are not named "core"

check:	check1 check2 check2b check3 check4 check6

OUTPUTS:
	@mkdir -p ${OUTPUTS}

check1: OUTPUTS
	@echo processing 1 ${SAMPLEDIR}/dooku.conf
	@rm -f core
	@echo >.gdbinit1  "file ${READWRITE} "
	@echo >>.gdbinit1 "set args --verbose --rootdir=${SAMPLEDIR}/dooku --config ${SAMPLEDIR}/dooku.conf --whackout=${OUTPUTS}/dookurecord.whack dooku--cassidy-net"
	${READWRITE} --rootdir=${SAMPLEDIR}/dooku --config ${SAMPLEDIR}/dooku.conf --whackout=${OUTPUTS}/dookurecord.whack dooku--cassidy-net 2>&1 | tee ${OUTPUTS}/dookuload.out | diff - dookuload.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi
	@strings ${OUTPUTS}/dookurecord.whack | grep pluto-whack-file >/dev/null
	@strings ${OUTPUTS}/dookurecord.whack | grep dooku--cassidy-net >/dev/null

check2: OUTPUTS
	@echo processing 2 ${SAMPLEDIR}/parker.conf parker1-jj0
	@rm -f core
	@echo >.gdbinit2  "file ${READWRITE} "
	@echo >>.gdbinit2 "set args --verbose --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj0 "
	@${READWRITE} --verbose --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj0 2>&1 | tee ${OUTPUTS}/parker1load.out | diff - output2.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi

check2b: OUTPUTS
	@echo processing 2b ${SAMPLEDIR}/parker.conf parker1-jj2
	@rm -f core
	@echo >.gdbinit2b  "file ${READWRITE} "
	@echo >>.gdbinit2b "set args --verbose --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj2 ikev2:parker--jj "
	@${READWRITE} --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj2 ikev2:parker--jj 2>&1 | tee ${OUTPUTS}/parkerload.out | diff - parkerload.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi
	@strings ${OUTPUTS}/parkerrecord.whack | grep pluto-whack-file >/dev/null
	@strings ${OUTPUTS}/parkerrecord.whack | grep parker1--jj2 >/dev/null
	@strings ${OUTPUTS}/parkerrecord.whack | grep ikev2:parker--jj >/dev/null
	@strings ${OUTPUTS}/parkerrecord.whack | grep parker01.emmjay.credil.org >/dev/null

check3: OUTPUTS
	@echo processing 3 ${SAMPLEDIR}/parker.conf with --all
	@rm -f core
	@echo >.gdbinit3 "file ${READWRITE} "
	@echo >>.gdbinit3 "set args ${TEST3ARGS}"
	@${READWRITE} ${TEST3ARGS} 2>&1 | tee ${OUTPUTS}/parkerload2.out | diff - parkerload2.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi
	@strings ${OUTPUTS}/parkerrecord2.whack | grep pluto-whack-file >/dev/null
	@strings ${OUTPUTS}/parkerrecord2.whack | grep parker1--jj2 >/dev/null
	@strings ${OUTPUTS}/parkerrecord2.whack | grep ikev2:parker--jj >/dev/null
	@strings ${OUTPUTS}/parkerrecord2.whack | grep parker01.emmjay.credil.org >/dev/null

check4: OUTPUTS
	@echo processing 4 ${SAMPLEDIR}/h2h.conf with --all
	@rm -f core
	@echo >.gdbinit4 "file ${READWRITE} "
	@echo >>.gdbinit4 "set args ${TEST4ARGS}"
	@${READWRITE} ${TEST4ARGS} 2>&1 | tee ${OUTPUTS}/h2h.out | diff - h2h.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi
	@strings ${OUTPUTS}/h2h.whack | grep pluto-whack-file >/dev/null
	@strings ${OUTPUTS}/h2h.whack | grep mytunnel-ikev1 >/dev/null

check6: OUTPUTS
	@echo processing 6 c2-missing-trailing-newline.conf with --all
	@echo >.gdbinit6 "file ${READWRITE} "
	@echo >>.gdbinit6 "set args ${TEST6ARGS}"
	@${READWRITE} ${TEST6ARGS} 2>&1 | tee ${OUTPUTS}/c2-missing-trailing-newline.out | diff - c2-missing-trailing-newline.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi
#: no whack file, as it has an error
#@strings ${OUTPUTS}/c2-missing-trailing-newline.whack | grep pluto-whack-file >/dev/null
#@strings ${OUTPUTS}/c2-missing-trailing-newline.whack | grep home >/dev/null

update:
	-cp ${OUTPUTS}/parker1load.out  output2.txt
	-cp ${OUTPUTS}/parkerload2.out  parkerload2.txt
	-cp ${OUTPUTS}/dookuload.out    dookuload.txt
	-cp ${OUTPUTS}/parkerload.out   parkerload.txt
	-cp ${OUTPUTS}/h2h.out          h2h.txt
	-cp ${OUTPUTS}/c2-missing-trailing-newline.out        c2-missing-trailing-newline.txt

clean:
	-rm core


