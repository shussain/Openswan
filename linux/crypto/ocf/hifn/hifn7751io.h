#ifndef __HIFN7751IO_H__
#define __HIFN7751IO_H__

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/io.h>
#include "hifn7751var.h"

static __inline u_int32_t
READ_REG_0(struct hifn_softc *sc, bus_size_t reg)
{
	u_int32_t v = readl(sc->sc_bar0 + reg);
	sc->sc_bar0_lastreg = (bus_size_t) -1;
	return (v);
}
#define	WRITE_REG_0(sc, reg, val)	hifn_write_reg_0(sc, reg, val)

static __inline u_int32_t
READ_REG_1(struct hifn_softc *sc, bus_size_t reg)
{
	u_int32_t v = readl(sc->sc_bar1 + reg);
	sc->sc_bar1_lastreg = (bus_size_t) -1;
	return (v);
}
#define	WRITE_REG_1(sc, reg, val)	hifn_write_reg_1(sc, reg, val)

#endif // __HIFN7751IO_H__
