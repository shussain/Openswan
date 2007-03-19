

/*
 *  circular.c - a utility for debugfs
 *
 *  Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License version
 *	2 as published by the Free Software Foundation.
 *
 *  debugfs is for people to use instead of /proc or /sys.
 *  See Documentation/DocBook/kernel-api for more details.
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/debugfs_circular.h>

static int default_open(struct inode *inode, struct file *file)
{
	if (inode->u.generic_ip)
		file->private_data = inode->u.generic_ip;

	return 0;
}

static ssize_t read_file_circitem(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[128];
	int len;
	struct debugfs_circular_item *val = file->private_data;

	len = snprintf(buf, 128, "0x%16llx 0x%16llx\n", val->when, val->what);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_circ = {
	.read =		read_file_circitem,
	.open =		default_open,
};


static ssize_t read_file_circnext(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[16];
	int len;
	struct debugfs_circular *val = file->private_data;

	len = snprintf(buf, 16, "%u\n", atomic_read(&val->next) & val->mask);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_circ_next = {
	.read =		read_file_circnext,
	.open =		default_open,
};

/**
 * debugfs_create_circular - create a directory in the debugfs filesystem that is used to read and write 64K arrays of telemetry
 *
 * @name: a pointer to a string containing the name of the file to create.
 * @mode: the permission that the file should have
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this paramater is NULL, then the
 *          dir will be created in the root of the debugfs filesystem.
 * @value: a value-return pointer to an array of type debugfs_circular
 *
 * This function creates a dir in debugfs with the given name that
 * contains 65536 files, each one will return the two item value at that
 * slot of the debugfs_circular.  Item one is of type jiffies_t,
 * and item two is a u32.
 *
 * This function will return a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the debugfs_remove_circular() function when the
 * dir is to be removed (no automatic cleanup happens if your module is
 * unloaded, you are responsible here.)  If an error occurs, NULL will be
 * returned.
 *
 * If debugfs is not enabled in the kernel, the value -ENODEV will be
 * returned.  It is not wise to check for this value, but rather, check for
 * NULL or !NULL instead as to eliminate the need for #ifdef in the calling
 * code.
 */
struct debugfs_circular *debugfs_create_circular(const char *name, mode_t mode,
						 struct dentry *parent)
{
	struct debugfs_circular *dfc;
	char  fname[32];
	int   i;
	struct dentry *de;

	dfc = vmalloc(sizeof(*dfc));
	if(!dfc) return NULL;

	dfc->items = vmalloc(sizeof(*dfc->items)*DEBUGFS_CIRCULAR_SIZE);
	dfc->mask = DEBUGFS_CIRCULAR_MASK;
	
	dfc->dir = debugfs_create_dir(name, parent);
	for(i=0; i<DEBUGFS_CIRCULAR_SIZE; i++) {
		snprintf(fname, 32, "%05u", i);
		
		de=debugfs_create_file(fname, mode, dfc->dir,
				       &dfc->items[i], &fops_circ);;
	}
	
	de=debugfs_create_file("next", mode & 0444, dfc->dir,
			       dfc, &fops_circ_next);

	return dfc;
}
EXPORT_SYMBOL_GPL(debugfs_create_circular);

