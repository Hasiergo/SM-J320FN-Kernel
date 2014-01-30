/*
 * Compressed RAM block device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *               2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 */

#define KMSG_COMPONENT "zram"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#ifdef CONFIG_ZRAM_DEBUG
#define DEBUG
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
<<<<<<< HEAD
#include <linux/idr.h>
=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

#include "zram_drv.h"

/* Globals */
static int zram_major;
<<<<<<< HEAD

static DEFINE_IDR(zram_index_idr);
/* idr index must be protected */
static DEFINE_MUTEX(zram_index_mutex);

static const char *default_compressor = "lz4";
=======
static struct zram *zram_devices;
static const char *default_compressor = "lzo";
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

/* Module params (documentation at end) */
static unsigned int num_devices = 1;

#define ZRAM_ATTR_RO(name)						\
static ssize_t zram_attr_##name##_show(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	struct zram *zram = dev_to_zram(d);				\
	return scnprintf(b, PAGE_SIZE, "%llu\n",			\
		(u64)atomic64_read(&zram->stats.name));			\
}									\
static struct device_attribute dev_attr_##name =			\
	__ATTR(name, S_IRUGO, zram_attr_##name##_show, NULL);

static inline int init_done(struct zram *zram)
{
	return zram->meta != NULL;
}

static inline struct zram *dev_to_zram(struct device *dev)
{
	return (struct zram *)dev_to_disk(dev)->private_data;
}

static ssize_t disksize_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", zram->disksize);
}

static ssize_t initstate_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u32 val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	val = init_done(zram);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t orig_data_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return scnprintf(buf, PAGE_SIZE, "%llu\n",
		(u64)(atomic64_read(&zram->stats.pages_stored)) << PAGE_SHIFT);
}

static ssize_t mem_used_total_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u64 val = 0;
	struct zram *zram = dev_to_zram(dev);
<<<<<<< HEAD

	down_read(&zram->init_lock);
	if (init_done(zram)) {
		struct zram_meta *meta = zram->meta;
		val = zs_get_total_pages(meta->mem_pool);
	}
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", val << PAGE_SHIFT);
}

/*
* We switched to per-cpu streams and this attr is not needed anymore.
* However, we will keep it around for some time, because:
* a) we may revert per-cpu streams in the future
* b) it's visible to user space and we need to follow our 2 years
*    retirement rule; but we already have a number of 'soon to be
*    altered' attrs, so max_comp_streams need to wait for the next
*    layoff cycle.
*/
static ssize_t max_comp_streams_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", num_online_cpus());
}

static ssize_t mem_limit_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u64 val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	val = zram->limit_pages;
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", val << PAGE_SHIFT);
}

static ssize_t mem_limit_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 limit;
	char *tmp;
	struct zram *zram = dev_to_zram(dev);

	limit = memparse(buf, &tmp);
	if (buf == tmp) /* no chars parsed, invalid input */
		return -EINVAL;

	down_write(&zram->init_lock);
	zram->limit_pages = PAGE_ALIGN(limit) >> PAGE_SHIFT;
	up_write(&zram->init_lock);

	return len;
}

static ssize_t mem_used_max_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u64 val = 0;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	if (init_done(zram))
		val = atomic_long_read(&zram->stats.max_used_pages);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", val << PAGE_SHIFT);
}

static ssize_t mem_used_max_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int err;
	unsigned long val;
	struct zram *zram = dev_to_zram(dev);

	err = kstrtoul(buf, 10, &val);
	if (err || val != 0)
		return -EINVAL;

	down_read(&zram->init_lock);
	if (init_done(zram)) {
		struct zram_meta *meta = zram->meta;
		atomic_long_set(&zram->stats.max_used_pages,
				zs_get_total_pages(meta->mem_pool));
	}
	up_read(&zram->init_lock);

	return len;
}

static ssize_t max_comp_streams_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	return len;
=======
	struct zram_meta *meta = zram->meta;

	down_read(&zram->init_lock);
	if (init_done(zram))
		val = zs_get_total_size_bytes(meta->mem_pool);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", val);
}

static ssize_t max_comp_streams_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	val = zram->max_comp_streams;
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t max_comp_streams_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int num;
	struct zram *zram = dev_to_zram(dev);
	int ret;

	ret = kstrtoint(buf, 0, &num);
	if (ret < 0)
		return ret;
	if (num < 1)
		return -EINVAL;

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		if (!zcomp_set_max_streams(zram->comp, num)) {
			pr_info("Cannot change max compression streams\n");
			ret = -EINVAL;
			goto out;
		}
	}

	zram->max_comp_streams = num;
	ret = len;
out:
	up_write(&zram->init_lock);
	return ret;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
}

static ssize_t comp_algorithm_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	size_t sz;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	sz = zcomp_available_show(zram->compressor, buf);
	up_read(&zram->init_lock);

	return sz;
}

static ssize_t comp_algorithm_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
<<<<<<< HEAD
	size_t sz;
	char compressor[CRYPTO_MAX_ALG_NAME];

	strlcpy(compressor, buf, sizeof(compressor));
	/* ignore trailing newline */
	sz = strlen(compressor);
	if (sz > 0 && compressor[sz - 1] == '\n')
		compressor[sz - 1] = 0x00;

	if (!zcomp_available_algorithm(compressor))
  		return -EINVAL;

=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	down_write(&zram->init_lock);
	if (init_done(zram)) {
		up_write(&zram->init_lock);
		pr_info("Can't change algorithm for initialized device\n");
		return -EBUSY;
	}
<<<<<<< HEAD

	strlcpy(zram->compressor, compressor, sizeof(compressor));
=======
	strlcpy(zram->compressor, buf, sizeof(zram->compressor));
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	up_write(&zram->init_lock);
	return len;
}

/* flag operations needs meta->tb_lock */
static int zram_test_flag(struct zram_meta *meta, u32 index,
			enum zram_pageflags flag)
{
<<<<<<< HEAD
	return meta->table[index].value & BIT(flag);
=======
	return meta->table[index].flags & BIT(flag);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
}

static void zram_set_flag(struct zram_meta *meta, u32 index,
			enum zram_pageflags flag)
{
<<<<<<< HEAD
	meta->table[index].value |= BIT(flag);
=======
	meta->table[index].flags |= BIT(flag);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
}

static void zram_clear_flag(struct zram_meta *meta, u32 index,
			enum zram_pageflags flag)
{
<<<<<<< HEAD
	meta->table[index].value &= ~BIT(flag);
}

static size_t zram_get_obj_size(struct zram_meta *meta, u32 index)
{
	return meta->table[index].value & (BIT(ZRAM_FLAG_SHIFT) - 1);
}

static void zram_set_obj_size(struct zram_meta *meta,
					u32 index, size_t size)
{
	unsigned long flags = meta->table[index].value >> ZRAM_FLAG_SHIFT;

	meta->table[index].value = (flags << ZRAM_FLAG_SHIFT) | size;
=======
	meta->table[index].flags &= ~BIT(flag);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
}

static inline int is_partial_io(struct bio_vec *bvec)
{
	return bvec->bv_len != PAGE_SIZE;
}

/*
 * Check if request is within bounds and aligned on zram logical blocks.
 */
static inline int valid_io_request(struct zram *zram, struct bio *bio)
{
	u64 start, end, bound;

	/* unaligned request */
<<<<<<< HEAD
	if (unlikely(bio->bi_sector & (ZRAM_SECTOR_PER_LOGICAL_BLOCK - 1)))
		return 0;
	if (unlikely(bio->bi_size & (ZRAM_LOGICAL_BLOCK_SIZE - 1)))
		return 0;

	start = bio->bi_sector;
	end = start + (bio->bi_size >> SECTOR_SHIFT);
=======
	if (unlikely(bio->bi_iter.bi_sector &
		     (ZRAM_SECTOR_PER_LOGICAL_BLOCK - 1)))
		return 0;
	if (unlikely(bio->bi_iter.bi_size & (ZRAM_LOGICAL_BLOCK_SIZE - 1)))
		return 0;

	start = bio->bi_iter.bi_sector;
	end = start + (bio->bi_iter.bi_size >> SECTOR_SHIFT);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	bound = zram->disksize >> SECTOR_SHIFT;
	/* out of range range */
	if (unlikely(start >= bound || end > bound || start > end))
		return 0;

	/* I/O request is valid */
	return 1;
}

static void zram_meta_free(struct zram_meta *meta)
{
	zs_destroy_pool(meta->mem_pool);
	vfree(meta->table);
	kfree(meta);
}

<<<<<<< HEAD
static struct zram_meta *zram_meta_alloc(int device_id, u64 disksize)
{
	size_t num_pages;
	char pool_name[8];
=======
static struct zram_meta *zram_meta_alloc(u64 disksize)
{
	size_t num_pages;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	struct zram_meta *meta = kmalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		goto out;

	num_pages = disksize >> PAGE_SHIFT;
	meta->table = vzalloc(num_pages * sizeof(*meta->table));
	if (!meta->table) {
		pr_err("Error allocating zram address table\n");
		goto free_meta;
	}

<<<<<<< HEAD
	snprintf(pool_name, sizeof(pool_name), "zram%d", device_id);
	meta->mem_pool = zs_create_pool(pool_name);
=======
	meta->mem_pool = zs_create_pool(GFP_NOIO | __GFP_HIGHMEM);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	if (!meta->mem_pool) {
		pr_err("Error creating memory pool\n");
		goto free_table;
	}

<<<<<<< HEAD
=======
	rwlock_init(&meta->tb_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	return meta;

free_table:
	vfree(meta->table);
free_meta:
	kfree(meta);
	meta = NULL;
out:
	return meta;
}

static void update_position(u32 *index, int *offset, struct bio_vec *bvec)
{
	if (*offset + bvec->bv_len >= PAGE_SIZE)
		(*index)++;
	*offset = (*offset + bvec->bv_len) % PAGE_SIZE;
}

static int page_zero_filled(void *ptr)
{
	unsigned int pos;
	unsigned long *page;

	page = (unsigned long *)ptr;

	for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
		if (page[pos])
			return 0;
	}

	return 1;
}

static void handle_zero_page(struct bio_vec *bvec)
{
	struct page *page = bvec->bv_page;
	void *user_mem;

	user_mem = kmap_atomic(page);
	if (is_partial_io(bvec))
		memset(user_mem + bvec->bv_offset, 0, bvec->bv_len);
	else
		clear_page(user_mem);
	kunmap_atomic(user_mem);

	flush_dcache_page(page);
}

<<<<<<< HEAD

/*
 * To protect concurrent access to the same index entry,
 * caller should hold this table index entry's bit_spinlock to
 * indicate this index entry is accessing.
 */
=======
/* NOTE: caller should hold meta->tb_lock with write-side */
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
static void zram_free_page(struct zram *zram, size_t index)
{
	struct zram_meta *meta = zram->meta;
	unsigned long handle = meta->table[index].handle;

	if (unlikely(!handle)) {
		/*
		 * No memory is allocated for zero filled pages.
		 * Simply clear zero page flag.
		 */
		if (zram_test_flag(meta, index, ZRAM_ZERO)) {
			zram_clear_flag(meta, index, ZRAM_ZERO);
			atomic64_dec(&zram->stats.zero_pages);
		}
		return;
	}

	zs_free(meta->mem_pool, handle);

<<<<<<< HEAD
	atomic64_sub(zram_get_obj_size(meta, index),
			&zram->stats.compr_data_size);
	atomic64_dec(&zram->stats.pages_stored);

	meta->table[index].handle = 0;
	zram_set_obj_size(meta, index, 0);
}

static int zram_decompress_page(struct zram *zram, struct zcomp_strm *zstrm,
		char *mem, u32 index)
=======
	atomic64_sub(meta->table[index].size, &zram->stats.compr_data_size);
	atomic64_dec(&zram->stats.pages_stored);

	meta->table[index].handle = 0;
	meta->table[index].size = 0;
}

static int zram_decompress_page(struct zram *zram, char *mem, u32 index)
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
{
	int ret = 0;
	unsigned char *cmem;
	struct zram_meta *meta = zram->meta;
	unsigned long handle;
<<<<<<< HEAD
	unsigned int size;

	bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
	handle = meta->table[index].handle;
	size = zram_get_obj_size(meta, index);

	if (!handle || zram_test_flag(meta, index, ZRAM_ZERO)) {
		bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
=======
	u16 size;

	read_lock(&meta->tb_lock);
	handle = meta->table[index].handle;
	size = meta->table[index].size;

	if (!handle || zram_test_flag(meta, index, ZRAM_ZERO)) {
		read_unlock(&meta->tb_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
		clear_page(mem);
		return 0;
	}

	cmem = zs_map_object(meta->mem_pool, handle, ZS_MM_RO);
<<<<<<< HEAD
	if (size == PAGE_SIZE) {
		copy_page(mem, cmem);
	} else {
		struct zcomp_strm *zstrm = zcomp_strm_find(zram->comp);

		ret = zcomp_decompress(zstrm, cmem, size, mem);
		zcomp_strm_release(zram->comp, zstrm);
	}
	zs_unmap_object(meta->mem_pool, handle);
	bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
=======
	if (size == PAGE_SIZE)
		copy_page(mem, cmem);
	else
		ret = zcomp_decompress(zram->comp, cmem, size, mem);
	zs_unmap_object(meta->mem_pool, handle);
	read_unlock(&meta->tb_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

	/* Should NEVER happen. Return bio error if it does. */
	if (unlikely(ret)) {
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);
<<<<<<< HEAD
=======
		atomic64_inc(&zram->stats.failed_reads);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
		return ret;
	}

	return 0;
}

static int zram_bvec_read(struct zram *zram, struct bio_vec *bvec,
			  u32 index, int offset, struct bio *bio)
{
	int ret;
	struct page *page;
	unsigned char *user_mem, *uncmem = NULL;
	struct zram_meta *meta = zram->meta;
<<<<<<< HEAD
	void *dzstrm;
	page = bvec->bv_page;

	bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
	if (unlikely(!meta->table[index].handle) ||
			zram_test_flag(meta, index, ZRAM_ZERO)) {
		bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
		handle_zero_page(bvec);
		return 0;
	}
	bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
=======
	page = bvec->bv_page;

	read_lock(&meta->tb_lock);
	if (unlikely(!meta->table[index].handle) ||
			zram_test_flag(meta, index, ZRAM_ZERO)) {
		read_unlock(&meta->tb_lock);
		handle_zero_page(bvec);
		return 0;
	}
	read_unlock(&meta->tb_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

	if (is_partial_io(bvec))
		/* Use  a temporary buffer to decompress the page */
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);

<<<<<<< HEAD
	dzstrm = zcomp_decompress_begin(zram->comp);
=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	user_mem = kmap_atomic(page);
	if (!is_partial_io(bvec))
		uncmem = user_mem;

	if (!uncmem) {
		pr_info("Unable to allocate temp memory\n");
		ret = -ENOMEM;
		goto out_cleanup;
	}

<<<<<<< HEAD
	ret = zram_decompress_page(zram, dzstrm, uncmem, index);

	zcomp_decompress_end(zram->comp, dzstrm);
	dzstrm = NULL;

=======
	ret = zram_decompress_page(zram, uncmem, index);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	/* Should NEVER happen. Return bio error if it does. */
	if (unlikely(ret))
		goto out_cleanup;

	if (is_partial_io(bvec))
		memcpy(user_mem + bvec->bv_offset, uncmem + offset,
				bvec->bv_len);

	flush_dcache_page(page);
	ret = 0;
<<<<<<< HEAD

out_cleanup:
	kunmap_atomic(user_mem);
	zcomp_decompress_end(zram->comp, dzstrm);
	if (is_partial_io(bvec))
		kfree(uncmem);

	return ret;
}

static inline void update_used_max(struct zram *zram,
					const unsigned long pages)
{
	int old_max, cur_max;

	old_max = atomic_long_read(&zram->stats.max_used_pages);

	do {
		cur_max = old_max;
		if (pages > cur_max)
			old_max = atomic_long_cmpxchg(
				&zram->stats.max_used_pages, cur_max, pages);
	} while (old_max != cur_max);
}

=======
out_cleanup:
	kunmap_atomic(user_mem);
	if (is_partial_io(bvec))
		kfree(uncmem);
	return ret;
}

>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
static int zram_bvec_write(struct zram *zram, struct bio_vec *bvec, u32 index,
			   int offset)
{
	int ret = 0;
<<<<<<< HEAD
	unsigned int clen;
	unsigned long handle = 0;
	struct page *page;
	unsigned char *user_mem, *cmem, *src, *uncmem = NULL;
	struct zram_meta *meta = zram->meta;
	struct zcomp_strm *zstrm = NULL;
	unsigned long alloced_pages;

	page = bvec->bv_page;
	if (is_partial_io(bvec)) {
		void *dzstrm;

=======
	size_t clen;
	unsigned long handle;
	struct page *page;
	unsigned char *user_mem, *cmem, *src, *uncmem = NULL;
	struct zram_meta *meta = zram->meta;
	struct zcomp_strm *zstrm;
	bool locked = false;

	page = bvec->bv_page;
	if (is_partial_io(bvec)) {
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
		/*
		 * This is a partial IO. We need to read the full page
		 * before to write the changes.
		 */
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);
		if (!uncmem) {
			ret = -ENOMEM;
			goto out;
		}
<<<<<<< HEAD

		dzstrm = zcomp_decompress_begin(zram->comp);
		ret = zram_decompress_page(zram, dzstrm, uncmem, index);
		zcomp_decompress_end(zram->comp, dzstrm);
=======
		ret = zram_decompress_page(zram, uncmem, index);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
		if (ret)
			goto out;
	}

<<<<<<< HEAD
compress_again:
	user_mem = kmap_atomic(page);
=======
	zstrm = zcomp_strm_find(zram->comp);
	locked = true;
	user_mem = kmap_atomic(page);

>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	if (is_partial_io(bvec)) {
		memcpy(uncmem + offset, user_mem + bvec->bv_offset,
		       bvec->bv_len);
		kunmap_atomic(user_mem);
		user_mem = NULL;
	} else {
		uncmem = user_mem;
	}

	if (page_zero_filled(uncmem)) {
<<<<<<< HEAD
		if (user_mem)
			kunmap_atomic(user_mem);
		/* Free memory associated with this sector now. */
		bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
		zram_free_page(zram, index);
		zram_set_flag(meta, index, ZRAM_ZERO);
		bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
=======
		kunmap_atomic(user_mem);
		/* Free memory associated with this sector now. */
		write_lock(&zram->meta->tb_lock);
		zram_free_page(zram, index);
		zram_set_flag(meta, index, ZRAM_ZERO);
		write_unlock(&zram->meta->tb_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

		atomic64_inc(&zram->stats.zero_pages);
		ret = 0;
		goto out;
	}

<<<<<<< HEAD
	zstrm = zcomp_strm_find(zram->comp);
	ret = zcomp_compress(zstrm, uncmem, &clen);
=======
	ret = zcomp_compress(zram->comp, zstrm, uncmem, &clen);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	if (!is_partial_io(bvec)) {
		kunmap_atomic(user_mem);
		user_mem = NULL;
		uncmem = NULL;
	}

	if (unlikely(ret)) {
		pr_err("Compression failed! err=%d\n", ret);
		goto out;
	}
<<<<<<< HEAD

=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	src = zstrm->buffer;
	if (unlikely(clen > max_zpage_size)) {
		clen = PAGE_SIZE;
		if (is_partial_io(bvec))
			src = uncmem;
	}

<<<<<<< HEAD
	/*
	 * handle allocation has 2 paths:
	 * a) fast path is executed with preemption disabled (for
	 *  per-cpu streams) and has __GFP_DIRECT_RECLAIM bit clear,
	 *  since we can't sleep;
	 * b) slow path enables preemption and attempts to allocate
	 *  the page with __GFP_DIRECT_RECLAIM bit set. we have to
	 *  put per-cpu compression stream and, thus, to re-do
	 *  the compression once handle is allocated.
	 *
	 * if we have a 'non-null' handle here then we are coming
	 * from the slow path and handle has already been allocated.
	 */
	if (!handle)
		handle = zs_malloc(meta->mem_pool, clen);

	if (!handle) {
		zcomp_strm_release(zram->comp, zstrm);
		zstrm = NULL;

		handle = zs_malloc(meta->mem_pool, clen);
		if (handle)
			goto compress_again;

		pr_info("Error allocating memory for compressed page: %u, size=%u\n",
=======
	handle = zs_malloc(meta->mem_pool, clen);
	if (!handle) {
		pr_info("Error allocating memory for compressed page: %u, size=%zu\n",
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
			index, clen);
		ret = -ENOMEM;
		goto out;
	}
<<<<<<< HEAD

	alloced_pages = zs_get_total_pages(meta->mem_pool);
	if (zram->limit_pages && alloced_pages > zram->limit_pages) {
		zs_free(meta->mem_pool, handle);
		ret = -ENOMEM;
		goto out;
	}

	update_used_max(zram, alloced_pages);

=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	cmem = zs_map_object(meta->mem_pool, handle, ZS_MM_WO);

	if ((clen == PAGE_SIZE) && !is_partial_io(bvec)) {
		src = kmap_atomic(page);
		copy_page(cmem, src);
		kunmap_atomic(src);
	} else {
		memcpy(cmem, src, clen);
	}

	zcomp_strm_release(zram->comp, zstrm);
<<<<<<< HEAD
	zstrm = NULL;
=======
	locked = false;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	zs_unmap_object(meta->mem_pool, handle);

	/*
	 * Free memory associated with this sector
	 * before overwriting unused sectors.
	 */
<<<<<<< HEAD
	bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
	zram_free_page(zram, index);

	meta->table[index].handle = handle;
	zram_set_obj_size(meta, index, clen);
	bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
=======
	write_lock(&zram->meta->tb_lock);
	zram_free_page(zram, index);

	meta->table[index].handle = handle;
	meta->table[index].size = clen;
	write_unlock(&zram->meta->tb_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

	/* Update stats */
	atomic64_add(clen, &zram->stats.compr_data_size);
	atomic64_inc(&zram->stats.pages_stored);
out:
<<<<<<< HEAD
	if (zstrm)
		zcomp_strm_release(zram->comp, zstrm);
	if (is_partial_io(bvec))
		kfree(uncmem);
=======
	if (locked)
		zcomp_strm_release(zram->comp, zstrm);
	if (is_partial_io(bvec))
		kfree(uncmem);
	if (ret)
		atomic64_inc(&zram->stats.failed_writes);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	return ret;
}

static int zram_bvec_rw(struct zram *zram, struct bio_vec *bvec, u32 index,
			int offset, struct bio *bio)
{
	int ret;
	int rw = bio_data_dir(bio);

	if (rw == READ) {
		atomic64_inc(&zram->stats.num_reads);
		ret = zram_bvec_read(zram, bvec, index, offset, bio);
	} else {
		atomic64_inc(&zram->stats.num_writes);
		ret = zram_bvec_write(zram, bvec, index, offset);
	}

<<<<<<< HEAD
	if (unlikely(ret)) {
		if (rw == READ)
			atomic64_inc(&zram->stats.failed_reads);
		else
			atomic64_inc(&zram->stats.failed_writes);
	}

=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	return ret;
}

/*
 * zram_bio_discard - handler on discard request
 * @index: physical block index in PAGE_SIZE units
 * @offset: byte offset within physical block
 */
static void zram_bio_discard(struct zram *zram, u32 index,
			     int offset, struct bio *bio)
{
<<<<<<< HEAD
	size_t n = bio->bi_size;
	struct zram_meta *meta = zram->meta;
=======
	size_t n = bio->bi_iter.bi_size;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

	/*
	 * zram manages data in physical block size units. Because logical block
	 * size isn't identical with physical block size on some arch, we
	 * could get a discard request pointing to a specific offset within a
	 * certain physical block.  Although we can handle this request by
	 * reading that physiclal block and decompressing and partially zeroing
	 * and re-compressing and then re-storing it, this isn't reasonable
	 * because our intent with a discard request is to save memory.  So
	 * skipping this logical block is appropriate here.
	 */
	if (offset) {
<<<<<<< HEAD
		if (n <= (PAGE_SIZE - offset))
			return;

		n -= (PAGE_SIZE - offset);
=======
		if (n < offset)
			return;

		n -= offset;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
		index++;
	}

	while (n >= PAGE_SIZE) {
<<<<<<< HEAD
		bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
		zram_free_page(zram, index);
		bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
		atomic64_inc(&zram->stats.notify_free);
=======
		/*
		 * Discard request can be large so the lock hold times could be
		 * lengthy.  So take the lock once per page.
		 */
		write_lock(&zram->meta->tb_lock);
		zram_free_page(zram, index);
		write_unlock(&zram->meta->tb_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
		index++;
		n -= PAGE_SIZE;
	}
}

static void zram_reset_device(struct zram *zram, bool reset_capacity)
{
	size_t index;
	struct zram_meta *meta;

	down_write(&zram->init_lock);
<<<<<<< HEAD

	zram->limit_pages = 0;

=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	if (!init_done(zram)) {
		up_write(&zram->init_lock);
		return;
	}

	meta = zram->meta;
	/* Free all pages that are still in this zram device */
	for (index = 0; index < zram->disksize >> PAGE_SHIFT; index++) {
		unsigned long handle = meta->table[index].handle;
		if (!handle)
			continue;

		zs_free(meta->mem_pool, handle);
	}

	zcomp_destroy(zram->comp);
<<<<<<< HEAD
	zram->max_comp_streams = 4;
=======
	zram->max_comp_streams = 1;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

	zram_meta_free(zram->meta);
	zram->meta = NULL;
	/* Reset stats */
	memset(&zram->stats, 0, sizeof(zram->stats));

	zram->disksize = 0;
<<<<<<< HEAD
	zram->max_comp_streams = NR_CPUS;
	set_capacity(zram->disk, 0);

	up_write(&zram->init_lock);

	/*
	 * Revalidate disk out of the init_lock to avoid lockdep splat.
	 * It's okay because disk's capacity is protected by init_lock
	 * so that revalidate_disk always sees up-to-date capacity.
	 */
	if (reset_capacity)
		revalidate_disk(zram->disk);
=======
	if (reset_capacity)
		set_capacity(zram->disk, 0);
	up_write(&zram->init_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
}

static ssize_t disksize_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 disksize;
	struct zcomp *comp;
	struct zram_meta *meta;
	struct zram *zram = dev_to_zram(dev);
	int err;

	disksize = memparse(buf, NULL);
	if (!disksize)
		return -EINVAL;

	disksize = PAGE_ALIGN(disksize);
<<<<<<< HEAD
	meta = zram_meta_alloc(zram->disk->first_minor, disksize);
	if (!meta)
		return -ENOMEM;

	comp = zcomp_create(zram->compressor);
=======
	meta = zram_meta_alloc(disksize);
	if (!meta)
		return -ENOMEM;

	comp = zcomp_create(zram->compressor, zram->max_comp_streams);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	if (IS_ERR(comp)) {
		pr_info("Cannot initialise %s compressing backend\n",
				zram->compressor);
		err = PTR_ERR(comp);
		goto out_free_meta;
	}

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		pr_info("Cannot change disksize for initialized device\n");
		err = -EBUSY;
		goto out_destroy_comp;
	}

	zram->meta = meta;
	zram->comp = comp;
	zram->disksize = disksize;
	set_capacity(zram->disk, zram->disksize >> SECTOR_SHIFT);
	up_write(&zram->init_lock);
<<<<<<< HEAD

	/*
	 * Revalidate disk out of the init_lock to avoid lockdep splat.
	 * It's okay because disk's capacity is protected by init_lock
	 * so that revalidate_disk always sees up-to-date capacity.
	 */
	revalidate_disk(zram->disk);

=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	return len;

out_destroy_comp:
	up_write(&zram->init_lock);
	zcomp_destroy(comp);
out_free_meta:
	zram_meta_free(meta);
	return err;
}

static ssize_t reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int ret;
	unsigned short do_reset;
	struct zram *zram;
	struct block_device *bdev;

<<<<<<< HEAD
	ret = kstrtou16(buf, 10, &do_reset);
	if (ret)
		return ret;

	if (!do_reset)
		return -EINVAL;

=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	zram = dev_to_zram(dev);
	bdev = bdget_disk(zram->disk, 0);

	if (!bdev)
		return -ENOMEM;

<<<<<<< HEAD
	mutex_lock(&bdev->bd_mutex);
	/* Do not reset an active device or claimed device */
	if (bdev->bd_openers || zram->claim) {
		mutex_unlock(&bdev->bd_mutex);
		bdput(bdev);
		return -EBUSY;
	}

	/* From now on, anyone can't open /dev/block/zram[0-9] */
	zram->claim = true;
	mutex_unlock(&bdev->bd_mutex);

	/* Make sure all the pending I/O are finished */
	fsync_bdev(bdev);
	zram_reset_device(zram);
	revalidate_disk(zram->disk);
	bdput(bdev);

	mutex_lock(&bdev->bd_mutex);
	zram->claim = false;
	mutex_unlock(&bdev->bd_mutex);

	return len;
}

static int zram_open(struct block_device *bdev, fmode_t mode)
{
	int ret = 0;
	struct zram *zram;

	WARN_ON(!mutex_is_locked(&bdev->bd_mutex));

	zram = bdev->bd_disk->private_data;
	/* zram was claimed to reset so open request fails */
	if (zram->claim)
		ret = -EBUSY;

=======
	/* Do not reset an active device! */
	if (bdev->bd_holders) {
		ret = -EBUSY;
		goto out;
	}

	ret = kstrtou16(buf, 10, &do_reset);
	if (ret)
		goto out;

	if (!do_reset) {
		ret = -EINVAL;
		goto out;
	}

	/* Make sure all pending I/O is finished */
	fsync_bdev(bdev);
	bdput(bdev);

	zram_reset_device(zram, true);
	return len;

out:
	bdput(bdev);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	return ret;
}

static void __zram_make_request(struct zram *zram, struct bio *bio)
{
<<<<<<< HEAD
	int i, offset;
	u32 index;
	struct bio_vec *bvec;

	index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
	offset = (bio->bi_sector &
=======
	int offset;
	u32 index;
	struct bio_vec bvec;
	struct bvec_iter iter;

	index = bio->bi_iter.bi_sector >> SECTORS_PER_PAGE_SHIFT;
	offset = (bio->bi_iter.bi_sector &
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
		  (SECTORS_PER_PAGE - 1)) << SECTOR_SHIFT;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		zram_bio_discard(zram, index, offset, bio);
		bio_endio(bio, 0);
		return;
	}

<<<<<<< HEAD
	bio_for_each_segment(bvec, bio, i) {
		int max_transfer_size = PAGE_SIZE - offset;

		if (bvec->bv_len > max_transfer_size) {
=======
	bio_for_each_segment(bvec, bio, iter) {
		int max_transfer_size = PAGE_SIZE - offset;

		if (bvec.bv_len > max_transfer_size) {
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
			/*
			 * zram_bvec_rw() can only make operation on a single
			 * zram page. Split the bio vector.
			 */
			struct bio_vec bv;

<<<<<<< HEAD
			bv.bv_page = bvec->bv_page;
			bv.bv_len = max_transfer_size;
			bv.bv_offset = bvec->bv_offset;
=======
			bv.bv_page = bvec.bv_page;
			bv.bv_len = max_transfer_size;
			bv.bv_offset = bvec.bv_offset;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

			if (zram_bvec_rw(zram, &bv, index, offset, bio) < 0)
				goto out;

<<<<<<< HEAD
			bv.bv_len = bvec->bv_len - max_transfer_size;
=======
			bv.bv_len = bvec.bv_len - max_transfer_size;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
			bv.bv_offset += max_transfer_size;
			if (zram_bvec_rw(zram, &bv, index + 1, 0, bio) < 0)
				goto out;
		} else
<<<<<<< HEAD
			if (zram_bvec_rw(zram, bvec, index, offset, bio) < 0)
				goto out;

		update_position(&index, &offset, bvec);
=======
			if (zram_bvec_rw(zram, &bvec, index, offset, bio) < 0)
				goto out;

		update_position(&index, &offset, &bvec);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	}

	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return;

out:
	bio_io_error(bio);
}

/*
 * Handler function for all zram I/O requests.
 */
<<<<<<< HEAD
static int zram_make_request(struct request_queue *queue, struct bio *bio)
=======
static void zram_make_request(struct request_queue *queue, struct bio *bio)
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
{
	struct zram *zram = queue->queuedata;

	down_read(&zram->init_lock);
	if (unlikely(!init_done(zram)))
		goto error;

	if (!valid_io_request(zram, bio)) {
		atomic64_inc(&zram->stats.invalid_io);
		goto error;
	}

	__zram_make_request(zram, bio);
	up_read(&zram->init_lock);

<<<<<<< HEAD
	return 0;
=======
	return;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

error:
	up_read(&zram->init_lock);
	bio_io_error(bio);
<<<<<<< HEAD
	return 0;
=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
}

static void zram_slot_free_notify(struct block_device *bdev,
				unsigned long index)
{
	struct zram *zram;
	struct zram_meta *meta;

	zram = bdev->bd_disk->private_data;
	meta = zram->meta;

<<<<<<< HEAD
	bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
	zram_free_page(zram, index);
	bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
=======
	write_lock(&meta->tb_lock);
	zram_free_page(zram, index);
	write_unlock(&meta->tb_lock);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	atomic64_inc(&zram->stats.notify_free);
}

static const struct block_device_operations zram_devops = {
<<<<<<< HEAD
	.open = zram_open,
=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	.swap_slot_free_notify = zram_slot_free_notify,
	.owner = THIS_MODULE
};

static DEVICE_ATTR(disksize, S_IRUGO | S_IWUSR,
		disksize_show, disksize_store);
static DEVICE_ATTR(initstate, S_IRUGO, initstate_show, NULL);
static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_store);
static DEVICE_ATTR(orig_data_size, S_IRUGO, orig_data_size_show, NULL);
static DEVICE_ATTR(mem_used_total, S_IRUGO, mem_used_total_show, NULL);
<<<<<<< HEAD
static DEVICE_ATTR(mem_limit, S_IRUGO | S_IWUSR, mem_limit_show,
		mem_limit_store);
static DEVICE_ATTR(mem_used_max, S_IRUGO | S_IWUSR, mem_used_max_show,
		mem_used_max_store);
=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
static DEVICE_ATTR(max_comp_streams, S_IRUGO | S_IWUSR,
		max_comp_streams_show, max_comp_streams_store);
static DEVICE_ATTR(comp_algorithm, S_IRUGO | S_IWUSR,
		comp_algorithm_show, comp_algorithm_store);

ZRAM_ATTR_RO(num_reads);
ZRAM_ATTR_RO(num_writes);
ZRAM_ATTR_RO(failed_reads);
ZRAM_ATTR_RO(failed_writes);
ZRAM_ATTR_RO(invalid_io);
ZRAM_ATTR_RO(notify_free);
ZRAM_ATTR_RO(zero_pages);
ZRAM_ATTR_RO(compr_data_size);

static struct attribute *zram_disk_attrs[] = {
	&dev_attr_disksize.attr,
	&dev_attr_initstate.attr,
	&dev_attr_reset.attr,
	&dev_attr_num_reads.attr,
	&dev_attr_num_writes.attr,
	&dev_attr_failed_reads.attr,
	&dev_attr_failed_writes.attr,
	&dev_attr_invalid_io.attr,
	&dev_attr_notify_free.attr,
	&dev_attr_zero_pages.attr,
	&dev_attr_orig_data_size.attr,
	&dev_attr_compr_data_size.attr,
	&dev_attr_mem_used_total.attr,
<<<<<<< HEAD
	&dev_attr_mem_limit.attr,
	&dev_attr_mem_used_max.attr,
=======
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	&dev_attr_max_comp_streams.attr,
	&dev_attr_comp_algorithm.attr,
	NULL,
};

static struct attribute_group zram_disk_attr_group = {
	.attrs = zram_disk_attrs,
};

<<<<<<< HEAD
static int zram_add(void)
{
	struct zram *zram;
	struct request_queue *queue;
	int ret, device_id;

	zram = kzalloc(sizeof(struct zram), GFP_KERNEL);
	if (!zram)
		return -ENOMEM;

	ret = idr_alloc(&zram_index_idr, zram, 0, 0, GFP_KERNEL);

	if (ret < 0)
		goto out_free_dev;
	device_id = ret;
=======
static int create_device(struct zram *zram, int device_id)
{
	int ret = -ENOMEM;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

	init_rwsem(&zram->init_lock);

	zram->queue = blk_alloc_queue(GFP_KERNEL);
	if (!zram->queue) {
		pr_err("Error allocating disk queue for device %d\n",
			device_id);
<<<<<<< HEAD
		ret = -ENOMEM;
		goto out_free_idr;
=======
		goto out;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	}

	blk_queue_make_request(zram->queue, zram_make_request);
	zram->queue->queuedata = zram;

<<<<<<< HEAD
	/* gendisk structure */
=======
	 /* gendisk structure */
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	zram->disk = alloc_disk(1);
	if (!zram->disk) {
		pr_warn("Error allocating disk structure for device %d\n",
			device_id);
		goto out_free_queue;
	}

	zram->disk->major = zram_major;
	zram->disk->first_minor = device_id;
	zram->disk->fops = &zram_devops;
	zram->disk->queue = zram->queue;
	zram->disk->private_data = zram;
	snprintf(zram->disk->disk_name, 16, "zram%d", device_id);

<<<<<<< HEAD
=======
	__set_bit(QUEUE_FLAG_FAST, &zram->queue->queue_flags);
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	/* Actual capacity set using syfs (/sys/block/zram<id>/disksize */
	set_capacity(zram->disk, 0);
	/* zram devices sort of resembles non-rotational disks */
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, zram->disk->queue);
	/*
	 * To ensure that we always get PAGE_SIZE aligned
	 * and n*PAGE_SIZED sized I/O requests.
	 */
	blk_queue_physical_block_size(zram->disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(zram->disk->queue,
					ZRAM_LOGICAL_BLOCK_SIZE);
	blk_queue_io_min(zram->disk->queue, PAGE_SIZE);
	blk_queue_io_opt(zram->disk->queue, PAGE_SIZE);
	zram->disk->queue->limits.discard_granularity = PAGE_SIZE;
	zram->disk->queue->limits.max_discard_sectors = UINT_MAX;
	/*
	 * zram_bio_discard() will clear all logical blocks if logical block
	 * size is identical with physical block size(PAGE_SIZE). But if it is
	 * different, we will skip discarding some parts of logical blocks in
	 * the part of the request range which isn't aligned to physical block
	 * size.  So we can't ensure that all discarded logical blocks are
	 * zeroed.
	 */
	if (ZRAM_LOGICAL_BLOCK_SIZE == PAGE_SIZE)
		zram->disk->queue->limits.discard_zeroes_data = 1;
	else
		zram->disk->queue->limits.discard_zeroes_data = 0;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, zram->disk->queue);

	add_disk(zram->disk);

	ret = sysfs_create_group(&disk_to_dev(zram->disk)->kobj,
				&zram_disk_attr_group);
	if (ret < 0) {
		pr_warn("Error creating sysfs group");
		goto out_free_disk;
	}
	strlcpy(zram->compressor, default_compressor, sizeof(zram->compressor));
	zram->meta = NULL;
<<<<<<< HEAD

	pr_info("Added device: %s\n", zram->disk->disk_name);
	return device_id;
=======
	zram->max_comp_streams = 1;
	return 0;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

out_free_disk:
	del_gendisk(zram->disk);
	put_disk(zram->disk);
out_free_queue:
<<<<<<< HEAD
	blk_cleanup_queue(queue);
out_free_idr:
	idr_remove(&zram_index_idr, device_id);
out_free_dev:
	kfree(zram);
	return ret;
}

static int zram_remove(struct zram *zram)
{
	struct block_device *bdev;

	bdev = bdget_disk(zram->disk, 0);
	if (!bdev)
		return -ENOMEM;

	mutex_lock(&bdev->bd_mutex);
	if (bdev->bd_openers || zram->claim) {
		mutex_unlock(&bdev->bd_mutex);
		bdput(bdev);
		return -EBUSY;
	}

	zram->claim = true;
	mutex_unlock(&bdev->bd_mutex);

	/*
	 * Remove sysfs first, so no one will perform a disksize
	 * store while we destroy the devices. This also helps during
	 * hot_remove -- zram_reset_device() is the last holder of
	 * ->init_lock, no later/concurrent disksize_store() or any
	 * other sysfs handlers are possible.
	 */
	sysfs_remove_group(&disk_to_dev(zram->disk)->kobj,
			&zram_disk_attr_group);

	/* Make sure all the pending I/O are finished */
	fsync_bdev(bdev);
	zram_reset_device(zram);
	bdput(bdev);

	pr_info("Removed device: %s\n", zram->disk->disk_name);

	idr_remove(&zram_index_idr, zram->disk->first_minor);
	blk_cleanup_queue(zram->disk->queue);
	del_gendisk(zram->disk);
	put_disk(zram->disk);
	kfree(zram);
	return 0;
}

/* zram-control sysfs attributes */
static ssize_t hot_add_show(struct class *class,
			struct class_attribute *attr,
			char *buf)
{
	int ret;

	mutex_lock(&zram_index_mutex);
	ret = zram_add();
	mutex_unlock(&zram_index_mutex);

	if (ret < 0)
		return ret;
	return scnprintf(buf, PAGE_SIZE, "%d\n", ret);
}

static ssize_t hot_remove_store(struct class *class,
			struct class_attribute *attr,
			const char *buf,
			size_t count)
{
	struct zram *zram;
	int ret, dev_id;

	/* dev_id is gendisk->first_minor, which is `int' */
	ret = kstrtoint(buf, 10, &dev_id);
	if (ret)
		return ret;
	if (dev_id < 0)
		return -EINVAL;

	mutex_lock(&zram_index_mutex);

	zram = idr_find(&zram_index_idr, dev_id);
	if (zram)
		ret = zram_remove(zram);
	else
		ret = -ENODEV;

	mutex_unlock(&zram_index_mutex);
	return ret ? ret : count;
}

static struct class_attribute zram_control_class_attrs[] = {
	__ATTR_RO(hot_add),
	__ATTR_WO(hot_remove),
	__ATTR_NULL,
};

static struct class zram_control_class = {
	.name		= "zram-control",
	.owner		= THIS_MODULE,
	.class_attrs	= zram_control_class_attrs,
};

static int zram_remove_cb(int id, void *ptr, void *data)
{
	zram_remove(ptr);
	return 0;
}

static void destroy_devices(void)
{
	class_unregister(&zram_control_class);
	idr_for_each(&zram_index_idr, &zram_remove_cb, NULL);
	idr_destroy(&zram_index_idr);
	unregister_blkdev(zram_major, "zram");
}

static uint32_t total_mem_usage_percent = 30;
static ssize_t mem_free_percent(void)
{
	unsigned long mem_used_pages = 0;
	int i = 0;
	struct zram *zram = NULL;
	unsigned long total_zram_pages = totalram_pages * total_mem_usage_percent / 100;
	for (i = 0; i < num_devices; i++) {
		if(!down_read_trylock(&zram->init_lock))
			return -1;
		if(init_done(zram) && zram->meta && zram->meta->mem_pool)
			mem_used_pages += zs_get_total_pages(zram->meta->mem_pool);
		up_read(&zram->init_lock);
	}
	pr_info("ZRAM: totalram_pages: %lu, total_zram_pages: %lu, mem_used_pages: %lu\r\n",
			totalram_pages, total_zram_pages, mem_used_pages);
	return (mem_used_pages >= total_zram_pages)
			? 0
			: ((total_zram_pages - mem_used_pages) * 100 / total_zram_pages);
}

=======
	blk_cleanup_queue(zram->queue);
out:
	return ret;
}

static void destroy_device(struct zram *zram)
{
	sysfs_remove_group(&disk_to_dev(zram->disk)->kobj,
			&zram_disk_attr_group);

>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	del_gendisk(zram->disk);
	put_disk(zram->disk);

	blk_cleanup_queue(zram->queue);
}

static int __init zram_init(void)
{
<<<<<<< HEAD
	int ret;

	ret = class_register(&zram_control_class);
	if (ret) {
		pr_warn("Unable to register zram-control class\n");
		return ret;
=======
	int ret, dev_id;

	if (num_devices > max_num_devices) {
		pr_warn("Invalid value for num_devices: %u\n",
				num_devices);
		ret = -EINVAL;
		goto out;
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	}

	zram_major = register_blkdev(0, "zram");
	if (zram_major <= 0) {
		pr_warn("Unable to get major number\n");
<<<<<<< HEAD
		class_unregister(&zram_control_class);
		return -EBUSY;
	}

	while (num_devices != 0) {
		mutex_lock(&zram_index_mutex);
		ret = zram_add();
		mutex_unlock(&zram_index_mutex);
		if (ret < 0)
			goto out_error;
		num_devices--;
	}

	return 0;

out_error:
	destroy_devices();
=======
		ret = -EBUSY;
		goto out;
	}

	/* Allocate the device array and initialize each one */
	zram_devices = kzalloc(num_devices * sizeof(struct zram), GFP_KERNEL);
	if (!zram_devices) {
		ret = -ENOMEM;
		goto unregister;
	}

	for (dev_id = 0; dev_id < num_devices; dev_id++) {
		ret = create_device(&zram_devices[dev_id], dev_id);
		if (ret)
			goto free_devices;
	}

	pr_info("Created %u device(s) ...\n", num_devices);

	return 0;

free_devices:
	while (dev_id)
		destroy_device(&zram_devices[--dev_id]);
	kfree(zram_devices);
unregister:
	unregister_blkdev(zram_major, "zram");
out:
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
	return ret;
}

static void __exit zram_exit(void)
{
<<<<<<< HEAD
	destroy_devices();
=======
	int i;
	struct zram *zram;

	for (i = 0; i < num_devices; i++) {
		zram = &zram_devices[i];

		destroy_device(zram);
		/*
		 * Shouldn't access zram->disk after destroy_device
		 * because destroy_device already released zram->disk.
		 */
		zram_reset_device(zram, false);
	}

	unregister_blkdev(zram_major, "zram");

	kfree(zram_devices);
	pr_debug("Cleanup done!\n");
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.
}

module_init(zram_init);
module_exit(zram_exit);

module_param(num_devices, uint, 0);
<<<<<<< HEAD
MODULE_PARM_DESC(num_devices, "Number of pre-created zram devices");
=======
MODULE_PARM_DESC(num_devices, "Number of zram devices");
>>>>>>> 426b56b75428... Rebase zram and zsmalloc from 3.15.

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
MODULE_DESCRIPTION("Compressed RAM Block Device");
