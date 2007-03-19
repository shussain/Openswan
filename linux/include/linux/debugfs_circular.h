/*
 *  debugfs_circular.h - a circular buffer for debug telemetry
 *
 *  Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License version
 *	2 as published by the Free Software Foundation.
 *
 *  debugfs is for people to use instead of /proc or /sys.
 *  See Documentation/DocBook/kernel-api for more details.
 */

#ifndef _DEBUGFS_CIRCULAR_H

#include <linux/jiffies.h>

struct debugfs_circular_item {
	u64      when;
	u64      what;
};

struct debugfs_circular {
	atomic_t                      next;
	uint                          mask;
	struct dentry                *dir;
	struct debugfs_circular_item *items;
};

#if defined(CONFIG_DEBUG_FS)
extern struct debugfs_circular *debugfs_create_circular(const char *name,
							mode_t mode,
							struct dentry *parent);

#else
static inline struct debugfs_circular *debugfs_create_circular(const char *name,
						     mode_t mode,
						     struct dentry *parent)
{
	return ERR_PTR(-ENODEV);
}
#endif

	
#define DEBUGFS_CIRCULAR_SHIFT 16
#define DEBUGFS_CIRCULAR_SIZE  (1 << DEBUGFS_CIRCULAR_SHIFT)
#define DEBUGFS_CIRCULAR_MASK  (DEBUGFS_CIRCULAR_SIZE-1)

#if defined(CONFIG_DEBUG_FS)
static inline void debugfs_circular_stamp(struct debugfs_circular *dfc, u64 value)
{
	uint where = atomic_inc_return(&dfc->next);
	where = where & dfc->mask;

	dfc->items[where].when = get_jiffies_64();
	dfc->items[where].what = value;
}
#else
#define debugfs_circular_stamp(dfc, value) do {} while(0)
#endif
	

#define _DEBUGFS_CIRCULAR_H
#endif /* _DEBUGFS_CIRCULAR_H */
