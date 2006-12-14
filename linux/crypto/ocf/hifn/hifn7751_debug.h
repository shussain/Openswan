#ifndef __HIFN7751_DEBUG_H__
#define __HIFN7751_DEBUG_H__

/* forward declarations */
static __inline u_int32_t READ_REG_0(struct hifn_softc *sc, bus_size_t reg);
static __inline u_int32_t READ_REG_1(struct hifn_softc *sc, bus_size_t reg);

static inline void __attribute__((unused))
hifn_dump_regs (struct hifn_softc *sc, const char *pre)
{
        uint32_t tmp;
        hifnprintf("-- %s\n", pre);
        hifnprintf("   HIFN_0_PUCNFG    = %08x\n", (tmp = READ_REG_0 (sc, HIFN_0_PUCNFG)));
        hifnprintf("   HIFN_0_PUISR     = %08x", (tmp = READ_REG_0 (sc, HIFN_0_PUISR)));
        hifnprintf(" # %s%s%s%s%s%s%s%s%s%s\n",
                        (tmp & HIFN_PUISR_CMDINVAL) ? "CMDINVAL " : "",
                        (tmp & HIFN_PUISR_DATAERR) ? "DATAERR " : "",
                        (tmp & HIFN_PUISR_SRCFIFO) ? "SRCFIFO " : "",
                        (tmp & HIFN_PUISR_DSTFIFO) ? "DSTFIFO " : "",
                        (tmp & HIFN_PUISR_DSTOVER) ? "DSTOVER " : "",
                        (tmp & HIFN_PUISR_SRCCMD) ? "SRCCMD " : "",
                        (tmp & HIFN_PUISR_SRCCTX) ? "SRCCTX " : "",
                        (tmp & HIFN_PUISR_SRCDATA) ? "SRCDATA " : "",
                        (tmp & HIFN_PUISR_DSTDATA) ? "DSTDATA " : "",
                        (tmp & HIFN_PUISR_DSTRESULT) ? "DSTRESULT " : "");
        hifnprintf("   HIFN_0_PUIER     = %08x", (tmp = READ_REG_0 (sc, HIFN_0_PUIER)));
        hifnprintf(" # %s%s%s%s%s%s%s%s%s%s\n",
                        (tmp & HIFN_PUIER_CMDINVAL) ? "CMDINVAL " : "",
                        (tmp & HIFN_PUIER_DATAERR) ? "DATAERR " : "",
                        (tmp & HIFN_PUIER_SRCFIFO) ? "SRCFIFO " : "",
                        (tmp & HIFN_PUIER_DSTFIFO) ? "DSTFIFO " : "",
                        (tmp & HIFN_PUIER_DSTOVER) ? "DSTOVER " : "",
                        (tmp & HIFN_PUIER_SRCCMD) ? "SRCCMD " : "",
                        (tmp & HIFN_PUIER_SRCCTX) ? "SRCCTX " : "",
                        (tmp & HIFN_PUIER_SRCDATA) ? "SRCDATA " : "",
                        (tmp & HIFN_PUIER_DSTDATA) ? "DSTDATA " : "",
                        (tmp & HIFN_PUIER_DSTRESULT) ? "DSTRESULT " : "");
        hifnprintf("   HIFN_0_PUSTAT    = %08x", (tmp = READ_REG_0 (sc, HIFN_0_PUSTAT)));
        hifnprintf(" # %s%s%s%s%s%s%s%s%s%s\n",
                        (tmp & HIFN_PUSTAT_CMDINVAL) ? "CMDINVAL " : "",
                        (tmp & HIFN_PUSTAT_DATAERR) ? "DATAERR " : "",
                        (tmp & HIFN_PUSTAT_SRCFIFO) ? "SRCFIFO " : "",
                        (tmp & HIFN_PUSTAT_DSTFIFO) ? "DSTFIFO " : "",
                        (tmp & HIFN_PUSTAT_DSTOVER) ? "DSTOVER " : "",
                        (tmp & HIFN_PUSTAT_SRCCMD) ? "SRCCMD " : "",
                        (tmp & HIFN_PUSTAT_SRCCTX) ? "SRCCTX " : "",
                        (tmp & HIFN_PUSTAT_SRCDATA) ? "SRCDATA " : "",
                        (tmp & HIFN_PUSTAT_DSTDATA) ? "DSTDATA " : "",
                        (tmp & HIFN_PUSTAT_DSTRESULT) ? "DSTRESULT " : "");
        hifnprintf("   HIFN_0_FIFOSTAT  = %08x\n", (tmp = READ_REG_0 (sc, HIFN_0_FIFOSTAT)));
        hifnprintf("   HIFN_0_FIFOCNFG  = %08x\n", (tmp = READ_REG_0 (sc, HIFN_0_FIFOCNFG)));
        hifnprintf("   HIFN_0_PUCTRL2   = %08x\n", (tmp = READ_REG_0 (sc, HIFN_0_PUCTRL2)));
        hifnprintf("   HIFN_1_DMA_CRAR  = %08x\n", (tmp = READ_REG_1 (sc, HIFN_1_DMA_CRAR)));
        hifnprintf("   HIFN_1_DMA_SRAR  = %08x\n", (tmp = READ_REG_1 (sc, HIFN_1_DMA_SRAR)));
        hifnprintf("   HIFN_1_DMA_RRAR  = %08x\n", (tmp = READ_REG_1 (sc, HIFN_1_DMA_RRAR)));
        hifnprintf("   HIFN_1_DMA_DRAR  = %08x\n", (tmp = READ_REG_1 (sc, HIFN_1_DMA_DRAR)));
        hifnprintf("   HIFN_1_DMA_CSR   = %08x", (tmp = READ_REG_1 (sc, HIFN_1_DMA_CSR)));
        hifnprintf(" # %s%s%s%s\n",
                        (tmp & HIFN_DMACSR_ILLW) ? "ILLW " : "",
                        (tmp & HIFN_DMACSR_ILLR) ? "ILLR " : "",
                        (tmp & HIFN_DMACSR_PUBDONE) ? "PUBDONE " : "",
                        (tmp & HIFN_DMACSR_ENGINE) ? "ENGINE " : "");
        hifnprintf("                               # C: %s%s%s%s%s%s\n",
                        (tmp & HIFN_DMACSR_C_CTRL_DIS) ? "CTRL_DIS " : "",
                        (tmp & HIFN_DMACSR_C_CTRL_ENA) ? "CTRL_ENA " : "",
                        (tmp & HIFN_DMACSR_C_ABORT) ? "ABORT " : "",
                        (tmp & HIFN_DMACSR_C_DONE) ? "DONE " : "",
                        (tmp & HIFN_DMACSR_C_LAST) ? "LAST " : "",
                        (tmp & HIFN_DMACSR_C_WAIT) ? "WAIT " : "");
        hifnprintf("                               # S: %s%s%s%s%s%s\n",
                        (tmp & HIFN_DMACSR_S_CTRL_DIS) ? "CTRL_DIS " : "",
                        (tmp & HIFN_DMACSR_S_CTRL_ENA) ? "CTRL_ENA " : "",
                        (tmp & HIFN_DMACSR_S_ABORT) ? "ABORT " : "",
                        (tmp & HIFN_DMACSR_S_DONE) ? "DONE " : "",
                        (tmp & HIFN_DMACSR_S_LAST) ? "LAST " : "",
                        (tmp & HIFN_DMACSR_S_WAIT) ? "WAIT " : "");
        hifnprintf("                               # D: %s%s%s%s%s%s%s\n",
                        (tmp & HIFN_DMACSR_D_CTRL_DIS) ? "CTRL_DIS " : "",
                        (tmp & HIFN_DMACSR_D_CTRL_ENA) ? "CTRL_ENA " : "",
                        (tmp & HIFN_DMACSR_D_ABORT) ? "ABORT " : "",
                        (tmp & HIFN_DMACSR_D_DONE) ? "DONE " : "",
                        (tmp & HIFN_DMACSR_D_LAST) ? "LAST " : "",
                        (tmp & HIFN_DMACSR_D_WAIT) ? "WAIT " : "",
                        (tmp & HIFN_DMACSR_D_OVER) ? "OVER " : "");
        hifnprintf("                               # R: %s%s%s%s%s%s%s\n",
                        (tmp & HIFN_DMACSR_R_CTRL_DIS) ? "CTRL_DIS " : "",
                        (tmp & HIFN_DMACSR_R_CTRL_ENA) ? "CTRL_ENA " : "",
                        (tmp & HIFN_DMACSR_R_ABORT) ? "ABORT " : "",
                        (tmp & HIFN_DMACSR_R_DONE) ? "DONE " : "",
                        (tmp & HIFN_DMACSR_R_LAST) ? "LAST " : "",
                        (tmp & HIFN_DMACSR_R_WAIT) ? "WAIT " : "",
                        (tmp & HIFN_DMACSR_R_OVER) ? "OVER " : "");
        hifnprintf("   HIFN_1_DMA_IER   = %08x", (tmp = READ_REG_1 (sc, HIFN_1_DMA_IER)));
        hifnprintf(" # %s%s%s%s\n",
                        (tmp & HIFN_DMAIER_ILLW) ? "ILLW " : "",
                        (tmp & HIFN_DMAIER_ILLR) ? "ILLR " : "",
                        (tmp & HIFN_DMAIER_PUBDONE) ? "PUBDONE " : "",
                        (tmp & HIFN_DMAIER_ENGINE) ? "ENGINE " : "");
        hifnprintf("                               # C: %s%s%s%s\n",
                        (tmp & HIFN_DMAIER_C_ABORT) ? "ABORT " : "",
                        (tmp & HIFN_DMAIER_C_DONE) ? "DONE " : "",
                        (tmp & HIFN_DMAIER_C_LAST) ? "LAST " : "",
                        (tmp & HIFN_DMAIER_C_WAIT) ? "WAIT " : "");
        hifnprintf("                               # S: %s%s%s%s\n",
                        (tmp & HIFN_DMAIER_S_ABORT) ? "ABORT " : "",
                        (tmp & HIFN_DMAIER_S_DONE) ? "DONE " : "",
                        (tmp & HIFN_DMAIER_S_LAST) ? "LAST " : "",
                        (tmp & HIFN_DMAIER_S_WAIT) ? "WAIT " : "");
        hifnprintf("                               # D: %s%s%s%s%s\n",
                        (tmp & HIFN_DMAIER_D_ABORT) ? "ABORT " : "",
                        (tmp & HIFN_DMAIER_D_DONE) ? "DONE " : "",
                        (tmp & HIFN_DMAIER_D_LAST) ? "LAST " : "",
                        (tmp & HIFN_DMAIER_D_WAIT) ? "WAIT " : "",
                        (tmp & HIFN_DMAIER_D_OVER) ? "OVER " : "");
        hifnprintf("                               # R: %s%s%s%s%s\n",
                        (tmp & HIFN_DMAIER_R_ABORT) ? "ABORT " : "",
                        (tmp & HIFN_DMAIER_R_DONE) ? "DONE " : "",
                        (tmp & HIFN_DMAIER_R_LAST) ? "LAST " : "",
                        (tmp & HIFN_DMAIER_R_WAIT) ? "WAIT " : "",
                        (tmp & HIFN_DMAIER_R_OVER) ? "OVER " : "");
        hifnprintf("   HIFN_1_DMA_CNFG  = %08x\n", (tmp = READ_REG_1 (sc, HIFN_1_DMA_CNFG)));
        hifnprintf("   HIFN_1_DMA_CNFG2 = %08x\n", (tmp = READ_REG_1 (sc, HIFN_1_DMA_CNFG2)));
}

static inline void __attribute__((unused))
hifn_dump_dma_rings (struct hifn_softc *sc)
{
	struct hifn_dma *dma;
        int i;
	dma = sc->sc_dma;

        hifnprintf ("-- dma rings\n");

        hifnprintf ("   cmd i=%d u=%d k=%d / %d ... ",
                        dma->cmdi, dma->cmdu, dma->cmdk, HIFN_D_CMD_RSIZE);
        for (i=0; i<HIFN_D_CMD_RSIZE; i++) {
                if ((i&7) == 0) hifnprintf ("\n      ");
                hifnprintf("%2d:[%c%c%c%c%c%c] ", i,
                        (dma->cmdr[i].l & HIFN_D_MASKDONEIRQ) ? 'M' : '_',
                        (dma->cmdr[i].l & HIFN_D_DESTOVER)    ? 'D' : '_',
                        (dma->cmdr[i].l & HIFN_D_OVER)        ? 'O' : '_',
                        (dma->cmdr[i].l & HIFN_D_LAST)        ? 'L' : '_',
                        (dma->cmdr[i].l & HIFN_D_JUMP)        ? 'J' : '_',
                        (dma->cmdr[i].l & HIFN_D_VALID)       ? 'V' : '_');
        }
        if ((i&7) != 1) hifnprintf ("\n");

        hifnprintf ("   src i=%d u=%d k=%d / %d ... ",
                        dma->srci, dma->srcu, dma->srck, HIFN_D_SRC_RSIZE);
        for (i=0; i<HIFN_D_SRC_RSIZE; i++) {
                if ((i&7) == 0) hifnprintf ("\n      ");
                hifnprintf("%2d:[%c%c%c%c%c%c] ", i,
                        (dma->srcr[i].l & HIFN_D_MASKDONEIRQ) ? 'M' : '_',
                        (dma->srcr[i].l & HIFN_D_DESTOVER)    ? 'D' : '_',
                        (dma->srcr[i].l & HIFN_D_OVER)        ? 'O' : '_',
                        (dma->srcr[i].l & HIFN_D_LAST)        ? 'L' : '_',
                        (dma->srcr[i].l & HIFN_D_JUMP)        ? 'J' : '_',
                        (dma->srcr[i].l & HIFN_D_VALID)       ? 'V' : '_');
        }
        if ((i&7) != 1) hifnprintf ("\n");

        hifnprintf ("   dst i=%d u=%d k=%d / %d ... ",
                        dma->dsti, dma->dstu, dma->dstk, HIFN_D_DST_RSIZE);
        for (i=0; i<HIFN_D_DST_RSIZE; i++) {
                if ((i&7) == 0) hifnprintf ("\n      ");
                hifnprintf("%2d:[%c%c%c%c%c%c] ", i,
                        (dma->dstr[i].l & HIFN_D_MASKDONEIRQ) ? 'M' : '_',
                        (dma->dstr[i].l & HIFN_D_DESTOVER)    ? 'D' : '_',
                        (dma->dstr[i].l & HIFN_D_OVER)        ? 'O' : '_',
                        (dma->dstr[i].l & HIFN_D_LAST)        ? 'L' : '_',
                        (dma->dstr[i].l & HIFN_D_JUMP)        ? 'J' : '_',
                        (dma->dstr[i].l & HIFN_D_VALID)       ? 'V' : '_');
        }
        if ((i&7) != 1) hifnprintf ("\n");

        hifnprintf ("   res i=%d u=%d k=%d / %d ... ",
                        dma->resi, dma->resu, dma->resk, HIFN_D_RES_RSIZE);
        for (i=0; i<HIFN_D_RES_RSIZE; i++) {
                if ((i&7) == 0) hifnprintf ("\n      ");
                hifnprintf("%2d:[%c%c%c%c%c%c] ", i,
                        (dma->resr[i].l & HIFN_D_MASKDONEIRQ) ? 'M' : '_',
                        (dma->resr[i].l & HIFN_D_DESTOVER)    ? 'D' : '_',
                        (dma->resr[i].l & HIFN_D_OVER)        ? 'O' : '_',
                        (dma->resr[i].l & HIFN_D_LAST)        ? 'L' : '_',
                        (dma->resr[i].l & HIFN_D_JUMP)        ? 'J' : '_',
                        (dma->resr[i].l & HIFN_D_VALID)       ? 'V' : '_');
        }
        if ((i&7) != 1) hifnprintf ("\n");
}

static inline void __attribute__((unused))
hifn_dump_buffers (struct hifn_softc *sc, int i)
{
	struct hifn_dma *dma;
        struct hifn_command *cmd;
        volatile uint8_t *cmdbuf;
        volatile hifn_base_command_t *basecmd;
        //volatile hifn_comp_command_t *compcmd;
        //volatile hifn_crypt_command_t *cryptcmd;
        //volatile hifn_mac_command_t *maccmd;
        volatile uint8_t *resbuf;
        volatile hifn_base_result_t *baseres;
        volatile hifn_comp_result_t *compres;
        volatile hifn_crypt_result_t *cryptres;
        volatile hifn_mac_result_t *macres;

        // --------------------------------------------------------------------

        if (!sc) {
                hifnprintf ("%s:%d sc==NULL\n", __FUNCTION__, __LINE__);
                return;
        }

	dma = sc->sc_dma;
        if (!dma) {
                hifnprintf ("%s:%d dma==NULL\n", __FUNCTION__, __LINE__);
                return;
        }

        cmd = dma->hifn_commands[i];
        if (!cmd) {
                hifnprintf ("%s:%d i=%d cmd==NULL\n", __FUNCTION__, __LINE__, i);
                return;
        }

        hifnprintf("-- i=%d dma=%p cmd=%p \n", i, dma, cmd);
        hifnprintf("   base_masks %04x # %s%s%s%s%s%s%s%s%s\n",
                cmd->base_masks, 
                (cmd->base_masks & HIFN_BASE_CMD_COMP) ? "COMP " : "",
                (cmd->base_masks & HIFN_BASE_CMD_PAD) ? "PAD " : "",
                (cmd->base_masks & HIFN_BASE_CMD_MAC) ? "MAC " : "",
                (cmd->base_masks & HIFN_BASE_CMD_CRYPT) ? "CRYPT " : "",
                (cmd->base_masks & HIFN_BASE_CMD_DISABLE_DEST_FIFO) ? "FIFO " : "",
                (cmd->base_masks & HIFN_BASE_CMD_COMMAND_MASK) ? "MASK " : "",
                (cmd->base_masks & HIFN_BASE_CMD_DECODE) ? "DECODE " : "",
                (cmd->base_masks & HIFN_BASE_CMD_READ_RAM) ? "RAM " : "",
                (cmd->base_masks & HIFN_BASE_CMD_WRITE_RAM) ? "RAM " : "");

        if (cmd->base_masks & HIFN_BASE_CMD_COMP) {
                hifnprintf("   comp_masks %04x # %s%s%s%s\n",
                        cmd->comp_masks, 
                        (cmd->comp_masks & HIFN_COMP_CMD_CLEAR_HIST) ? "CLEAR_HIST " : "",
                        (cmd->comp_masks & HIFN_COMP_CMD_UPDATE_HIST) ? "UPDATE_HIST " : "",
                        (cmd->comp_masks & HIFN_COMP_CMD_STRIP_0_RESTART) ? "STRIP_0/RESTART " : "",
                        (cmd->comp_masks & HIFN_COMP_CMD_MPPC) ? "MPPC " : "");
        }

        if (cmd->base_masks & HIFN_BASE_CMD_MAC) {
                hifnprintf("   mac_masks  %04x # ALG=%s MODE=%s %s%s%s\n",
                        cmd->mac_masks,
                        ({ const char *tmp="";
                         switch (cmd->mac_masks & HIFN_MAC_CMD_ALG_MASK) {
                         case HIFN_MAC_CMD_ALG_SHA1: tmp="SHA1"; break;
                         case HIFN_MAC_CMD_ALG_MD5:  tmp="MD5";  break;
                         }
                         tmp;
                         }),
                        ({ const char *tmp="";
                         switch (cmd->mac_masks & HIFN_MAC_CMD_MODE_MASK) {
                         case HIFN_MAC_CMD_MODE_HMAC: tmp="HMAC"; break;
                         case HIFN_MAC_CMD_MODE_HASH: tmp="HASH"; break;
                         case HIFN_MAC_CMD_MODE_FULL: tmp="FULL/SSL_MAC"; break;
                         }
                         tmp;
                         }),
                        (cmd->mac_masks & HIFN_MAC_CMD_TRUNC) ? "TRUNC " : "",
                        (cmd->mac_masks & HIFN_MAC_CMD_RESULT) ? "RESULT " : "",
                        (cmd->mac_masks & HIFN_MAC_CMD_APPEND) ? "APPEND " : "");
        }

        if (cmd->base_masks & HIFN_BASE_CMD_CRYPT) {
                hifnprintf("   crpt_masks %04x # ALG=%s MODE=%s %s%s%s\n",
                        cmd->cry_masks, 
                        ({ const char *tmp="";
                         switch (cmd->cry_masks & HIFN_CRYPT_CMD_ALG_MASK) {
                         case HIFN_CRYPT_CMD_ALG_DES:  tmp="DES";  break;
                         case HIFN_CRYPT_CMD_ALG_3DES: tmp="3DES"; break;
                         case HIFN_CRYPT_CMD_ALG_RC4:  tmp="RC4";  break;
                         case HIFN_CRYPT_CMD_ALG_AES:  tmp="AES";  break;
                         }
                         tmp;
                         }),
                        ({ const char *tmp="";
                         switch (cmd->cry_masks & HIFN_CRYPT_CMD_MODE_MASK) {
                         case HIFN_CRYPT_CMD_MODE_ECB: tmp="ECB"; break;
                         case HIFN_CRYPT_CMD_MODE_CBC: tmp="CBC"; break;
                         case HIFN_CRYPT_CMD_MODE_CFB: tmp="CFB"; break;
                         case HIFN_CRYPT_CMD_MODE_OFB: tmp="OFB"; break;
                         }
                         tmp;
                         }),
                        (cmd->cry_masks & HIFN_CRYPT_CMD_CLR_CTX) ? "CTX " : "",
                        (cmd->cry_masks & HIFN_CRYPT_CMD_NEW_KEY) ? "KEY " : "",
                        (cmd->cry_masks & HIFN_CRYPT_CMD_NEW_IV) ? "IV " : "");
        }

        hifnprintf("   dma.cmdr .p=%08x .l=%04x %s%s%s%s%s%s\n",
                        dma->cmdr[i].p, dma->cmdr[i].l & HIFN_D_LENGTH, 
                        (dma->cmdr[i].l & HIFN_D_MASKDONEIRQ) ? "MASKDONEIRQ " : "",
                        (dma->cmdr[i].l & HIFN_D_DESTOVER) ? "DESTOVER " : "",
                        (dma->cmdr[i].l & HIFN_D_OVER) ? "OVER " : "",
                        (dma->cmdr[i].l & HIFN_D_LAST) ? "LAST " : "",
                        (dma->cmdr[i].l & HIFN_D_JUMP) ? "JUMP " : "",
                        (dma->cmdr[i].l & HIFN_D_VALID) ? "VALID " : "");

        hifnprintf("   dma.srcr .p=%08x .l=%04x %s%s%s%s%s%s\n",
                        dma->srcr[i].p, dma->srcr[i].l & HIFN_D_LENGTH, 
                        (dma->srcr[i].l & HIFN_D_MASKDONEIRQ) ? "MASKDONEIRQ " : "",
                        (dma->srcr[i].l & HIFN_D_DESTOVER) ? "DESTOVER " : "",
                        (dma->srcr[i].l & HIFN_D_OVER) ? "OVER " : "",
                        (dma->srcr[i].l & HIFN_D_LAST) ? "LAST " : "",
                        (dma->srcr[i].l & HIFN_D_JUMP) ? "JUMP " : "",
                        (dma->srcr[i].l & HIFN_D_VALID) ? "VALID " : "");

        hifnprintf("   dma.dstr .p=%08x .l=%04x %s%s%s%s%s%s\n",
                        dma->dstr[i].p, dma->dstr[i].l & HIFN_D_LENGTH, 
                        (dma->dstr[i].l & HIFN_D_MASKDONEIRQ) ? "MASKDONEIRQ " : "",
                        (dma->dstr[i].l & HIFN_D_DESTOVER) ? "DESTOVER " : "",
                        (dma->dstr[i].l & HIFN_D_OVER) ? "OVER " : "",
                        (dma->dstr[i].l & HIFN_D_LAST) ? "LAST " : "",
                        (dma->dstr[i].l & HIFN_D_JUMP) ? "JUMP " : "",
                        (dma->dstr[i].l & HIFN_D_VALID) ? "VALID " : "");

        hifnprintf("   dma.resr .p=%08x .l=%04x %s%s%s%s%s%s\n",
                        dma->resr[i].p, dma->resr[i].l & HIFN_D_LENGTH, 
                        (dma->resr[i].l & HIFN_D_MASKDONEIRQ) ? "MASKDONEIRQ " : "",
                        (dma->resr[i].l & HIFN_D_DESTOVER) ? "DESTOVER " : "",
                        (dma->resr[i].l & HIFN_D_OVER) ? "OVER " : "",
                        (dma->resr[i].l & HIFN_D_LAST) ? "LAST " : "",
                        (dma->resr[i].l & HIFN_D_JUMP) ? "JUMP " : "",
                        (dma->resr[i].l & HIFN_D_VALID) ? "VALID " : "");

        // --------------------------------------------------------------------

        cmdbuf = dma->command_bufs[i];
        basecmd = (void*)cmdbuf;
        cmdbuf += sizeof (*basecmd);

        hifnprintf("-- cmd[%d] ses=%04x\n", i, basecmd->session_num);
        hifnprintf("   base masks              %04x # CMD=%s %s%s%s%s%s%s DEST_ALIGN=%d\n",
                        basecmd->masks,
                        ({ const char *tmp="";
                         switch (basecmd->masks & HIFN_BASE_CMD_COMMAND_MASK) {
                         case HIFN_BASE_CMD_ENCODE:    tmp="ENCODE";   break;
                         case HIFN_BASE_CMD_DECODE:    tmp="DECODE";   break;
                         case HIFN_BASE_CMD_READ_RAM:  tmp="READ_RAM"; break;
                         case HIFN_BASE_CMD_WRITE_RAM: tmp="READ_RAM"; break;
                         }
                         tmp;
                         }),
                        (basecmd->masks & HIFN_BASE_CMD_DISABLE_DEST_FIFO) ? "DISABLE_DEST_FIFO " : "",
                        (basecmd->masks & HIFN_BASE_CMD_CRYPT) ? "CRYPT " : "",
                        (basecmd->masks & HIFN_BASE_CMD_MAC) ? "MAC " : "",
                        (basecmd->masks & HIFN_BASE_CMD_PAD) ? "PAD " : "",
                        (basecmd->masks & HIFN_BASE_CMD_COMP) ? "COMP " : "",
                        (basecmd->masks & HIFN_BASE_CMD_IGNORE_DEST_COUNT) ? "IGNORE_DEST_COUNT " : "",
                        (basecmd->masks & HIFN_BASE_CMD_DEST_ALIGN_M) >> HIFN_BASE_CMD_DEST_ALIGN_S);
        hifnprintf("        session_num        %04x # %02x\n", 
                        basecmd->session_num,
                        basecmd->session_num & HIFN_BASE_CMD_SESSION_NUM);
        hifnprintf("        total_source_count %04x # %d\n", 
                        basecmd->total_source_count,
                        HIFN_BASE_CMD_SRCLEN_FROM_CMD(basecmd));
        hifnprintf("        total_dest_count   %04x # %d\n", 
                        le16_to_cpu(basecmd->total_dest_count),
                        HIFN_BASE_CMD_DSTLEN_FROM_CMD(basecmd));


        // --------------------------------------------------------------------

        resbuf = dma->result_bufs[i];
        baseres = (void*)resbuf;
        resbuf += sizeof (*baseres);

        hifnprintf("-- res[%d] ses=%04x\n", i, baseres->session_num);
        hifnprintf("   base masks              %04x # %s\n",
                        baseres->masks,
                        (baseres->masks & HIFN_BASE_RES_DEST_OVERRUN) ? "DESTOVER " : "");
        hifnprintf("        session_num        %04x # %02x\n", 
                        baseres->session_num,
                        baseres->session_num & HIFN_BASE_RES_SESSION_NUM);
        hifnprintf("        total_source_count %04x # %d\n", 
                        baseres->total_source_count,
                        HIFN_BASE_RES_SRCLEN_FROM_RES(baseres));
        hifnprintf("        total_dest_count   %04x # %d\n", 
                        baseres->total_dest_count,
                        HIFN_BASE_RES_DSTLEN_FROM_RES(baseres));

        if (cmd->base_masks & HIFN_BASE_CMD_COMP) {
                compres = (void*)baseres;
                resbuf += sizeof (*compres);
                hifnprintf("   comp masks              %04x # LCB=%d %s%s%s\n",
                                compres->masks,
                                (compres->masks & HIFN_COMP_RES_LCB_M) >> HIFN_COMP_RES_LCB_S,
                                (compres->masks & HIFN_COMP_RES_RESTART) ? "RESTART " : "",
                                (compres->masks & HIFN_COMP_RES_DCMP_SUCCESS) ? "DCMP_SUCCESS " : "",
                                (compres->masks & HIFN_COMP_RES_SOURCE_NOT_ZERO) ? "SOURCE_NOT_ZERO " : "");
                hifnprintf("        crc                %04x\n",
                                compres->crc);
        }

        if (cmd->base_masks & HIFN_BASE_CMD_MAC) {
                uint mac_len = 0;                       // TODO: figure out how wide MAC is
                macres = (void*)baseres;
                resbuf += sizeof (*macres) + mac_len;
                hifnprintf("   mac  masks              %04x # %s%s\n",
                                macres->masks,
                                (macres->masks & HIFN_MAC_RES_MISCOMPARE) ? "MISCOMPARE " : "",
                                (macres->masks & HIFN_MAC_RES_SOURCE_NOT_ZERO) ? "SOURCE_NOT_ZERO " : "");
                hifnprintf("        mac                %04x_%04x %04x_%04x %04x_%04x ...?\n",
                                macres->mac[0], macres->mac[1], macres->mac[2], 
                                macres->mac[3], macres->mac[4], macres->mac[5]);

        }

        if (cmd->base_masks & HIFN_BASE_CMD_CRYPT) {
                cryptres = (void*)baseres;
                resbuf += sizeof (*cryptres);
                hifnprintf("   cryp masks              %04x # %s\n",
                                cryptres->masks,
                                (cryptres->masks & HIFN_CRYPT_RES_SOURCE_NOT_ZERO) ? "SOURCE_NOT_ZERO " : "");
        }
}



#endif // __HIFN7751_DEBUG_H__
