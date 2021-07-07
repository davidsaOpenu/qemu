/* BlockDriver implementation for "vssim" format driver
 *
 * Copyright 2017 The Open University of Israel
 *
 * Author:
 *   Shimi Gersner <gersner@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/option.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qapi/qmp/qdict.h"
#include "qapi/error.h"
#include "block/block_int.h"
#include "trace.h"

#include "simulator/vssim_config_manager.h"
#include "simulator/ftl_sect_strategy.h"
#include "simulator/ftl_obj_strategy.h"
#include "simulator/uthash.h"

#define VSSIM_FILE_EXTENSION                  (".vssim")
#define VSSIM_FILE_EXTENSION_CHARACTER_LENGTH (sizeof(VSSIM_FILE_EXTENSION)-1)

#define VSSIM_DEFAULT_FILE_SIZE_IN_BYTES      (1024*1024*256)

#define VSSIM_BLOCK_OPT_SIMULATOR             ("simulator")

static bool g_device_open = false;

/*
* 2 level map:
*   1. partition -> object_map
*   2. object_map -> object
*/
typedef struct object{
    char **memory; /* 2 level memory; each block will correspond to a page */
    uint8_t pages; /* amount of pages */
} object;

typedef struct obj_map{
    object_id_t id;
    object data;
    UT_hash_handle hh; /* makes this structure hashable */
} obj_map;

typedef struct part_map{
    partition_id_t id;
    obj_map *objects; /* the object map of this partition */
    UT_hash_handle hh; /* makes this structure hashable */
} part_map;

// This is a block driver, yet we use it to pass object
typedef struct BDRVVSSIMState {
    // apparently, we can't decide, from the start, which one to use...
    // union
    // {
        char *memory;
        part_map *part;
    // };
    uint64_t size; /* size will represent the max size of an object / length of the sector based storage*/
    bool simulator;
} BDRVVSSIMState;

static QemuOptsList runtime_opts = {
    .name = "vssim",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "disk size",
        },
        {
            .name = VSSIM_BLOCK_OPT_SIMULATOR,
            .type = QEMU_OPT_BOOL,
            .help = "enable simulator"
        },
        { /* end of list */ }
    },
};

static void free_object_map(obj_map *map)
{
    obj_map *current_mapping, *tmp;
    uint8_t page;

    HASH_ITER(hh, map, current_mapping, tmp)
    {
        HASH_DEL(map, current_mapping);
        if (current_mapping->data.pages)
        {
            for(page = 0; page < current_mapping->data.pages; page++)
                g_free(current_mapping->data.memory[page]);
            g_free(current_mapping->data.memory);
        }
        g_free(current_mapping);
    }
}

static void free_part_memory(part_map *map)
{
    part_map *current_mapping, *tmp;

    HASH_ITER(hh, map, current_mapping, tmp)
    {
        free_object_map(map->objects);
        HASH_DEL(map, current_mapping);
        g_free(current_mapping);
    }
}

/*
*  Returns an object;
*  use create_if_needed if you want to create a new object
*  if one doesn't already exist
*/
static object* get_object(part_map **map, obj_id_t obj_loc, int create_if_needed)
{
    object *object = NULL;

    /* Find (or create if possible) the partition */
    part_map *part;
    HASH_FIND_INT((*map), &(obj_loc.partition_id), part);
    if (!part)
    {
        if (create_if_needed)
        {
            part = g_malloc(sizeof(part_map));
            part->id = obj_loc.partition_id;
            part->objects = NULL;
            HASH_ADD_INT((*map), id, part);
        }
        else
            goto exit;
    }

    /* Find (or create if possible) the object */
    obj_map *obj;
    HASH_FIND_INT(part->objects, &(obj_loc.object_id), obj);
    if (!obj)
    {
        if (create_if_needed)
        {
            obj = g_malloc(sizeof(obj_map));
            obj->id = obj_loc.object_id;
            obj->data.memory = NULL;
            obj->data.pages = 0;
            HASH_ADD_INT(part->objects, id, obj);
        }
        else
            goto exit;
    }
    object = &(obj->data);

    exit:
    return object;
}

static void write_to_object(QEMUIOVector *qiov, object *object, uint64_t offset,
        uint64_t bytes)
{
    uint8_t first_page = offset / GET_PAGE_SIZE(), last_page = first_page + bytes/GET_PAGE_SIZE(), page = first_page;
    if (!object)
        return;

    /* allocate memory if necessary */
    if (object->pages <= last_page)
    {
        if (!object->pages)
            object->memory = g_new(char *, last_page + 1);
        else
            object->memory = g_renew(char *, object->memory, last_page + 1);
        for(page = object->pages; page <= last_page; page++)
            object->memory[page] = g_malloc0(GET_PAGE_SIZE());
        object->pages = last_page + 1;
    }

    /* write page by page */
    for(page = first_page; page < last_page; page++)
        qemu_iovec_to_buf(qiov, page*GET_PAGE_SIZE(), object->memory[page], GET_PAGE_SIZE());
    qemu_iovec_to_buf(qiov, page*GET_PAGE_SIZE(), object->memory[page], bytes % GET_PAGE_SIZE());
}

static bool read_from_object(QEMUIOVector *qiov, object *object, uint64_t offset,
        uint64_t bytes)
{
    uint8_t first_page = offset / GET_PAGE_SIZE(), last_page = first_page + bytes/GET_PAGE_SIZE(), page = first_page;
    if (!object || object->pages <= last_page)
        return false;
    
    /* read page by page */
    for(page = first_page; page < last_page; page++)
        qemu_iovec_from_buf(qiov, page*GET_PAGE_SIZE(), object->memory[page], GET_PAGE_SIZE());
    qemu_iovec_from_buf(qiov, page*GET_PAGE_SIZE(), object->memory[page], bytes % GET_PAGE_SIZE());

    return true;
}

/* this function is from the old qemu */
static bool parse_metadata(uint8_t *metadata_mapping_address, unsigned int metadata_size, obj_id_t *obj_loc)
{
    char MAGIC[] = "eVSSIM_MAGIC";
    int MAGIC_LENGTH = 12;
    char *asACharArray = (char *)metadata_mapping_address;
    asACharArray[metadata_size - 1] = '\0';
    char *magicSuffixPtr = NULL;
    if (!memcmp(MAGIC, asACharArray, MAGIC_LENGTH))
    {
        asACharArray += MAGIC_LENGTH;
        magicSuffixPtr = strchr(asACharArray, '!');
        if (magicSuffixPtr)
        {
            char *seperatorPtr = strchr(asACharArray, '_');
            if (seperatorPtr != NULL)
            {
                *seperatorPtr = '\x00';
                *magicSuffixPtr = '\x00';
                obj_loc->partition_id = atoi(asACharArray);
                obj_loc->object_id = atoi(seperatorPtr + 1);
                *seperatorPtr = '_';
                *magicSuffixPtr = '!';
                return true;
            }
        }
    }
    return false;
}

// for some reason this function is called before vssim_config_manager, so we can't depend on STORAGE_STRATEGY here...
static int vssim_open(BlockDriverState *bs, QDict * dict, int flags,
                      Error **errp)
{
    BDRVVSSIMState *s = bs->opaque;
    QemuOpts *opts = NULL;
    trace_vssim_open(bs);

    // Only a single device is allowed due to global use of FTL
    if (g_device_open) {
        error_setg(errp, "vssim device allows only a single instance");
        return -EINVAL;
    }
    g_device_open = true;

    // Prase the drive options
    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, dict, &error_abort);
    s->size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE,
                                VSSIM_DEFAULT_FILE_SIZE_IN_BYTES);
    s->simulator = qemu_opt_get_bool(opts, VSSIM_BLOCK_OPT_SIMULATOR, true);
    qemu_opts_del(opts);

    // sector strategy, allocate the memory
    // if (STORAGE_STRATEGY == 1) 
        s->memory = qemu_blockalign0(bs, s->size);
    // else if(STORAGE_STRATEGY == 2) /* object strategy, we don't have to allocate anything for now */
        s->part = NULL;


    // Initialize FTL and logger
    if (s->simulator) {
        FTL_INIT();
        INIT_LOG_MANAGER();
        if (STORAGE_STRATEGY == 2)
            INIT_OBJ_STRATEGY();
    }

    // if (STORAGE_STRATEGY == 1)
        trace_vssim_initialized(bs, s->size, s->memory);

    return 0;
}

static void vssim_close(BlockDriverState *bs)
{
    BDRVVSSIMState *s = bs->opaque;
    trace_vssim_close(bs);

    // Destruct FTL
    if (s->simulator) {
        TERM_LOG_MANAGER();
        FTL_TERM();
        if (STORAGE_STRATEGY == 2)
            TERM_OBJ_STRATEGY();
    }

    // Clear memory
    // if (STORAGE_STRATEGY == 1) /* sector strategy */
    // {
        if (NULL != s->memory) {
            qemu_vfree(s->memory);
        }
    // }
    if (STORAGE_STRATEGY == 2) /* object strategy */
        free_part_memory(s->part);

    // Clear singleton state
    g_device_open = false;
}

static int object_prwv(BDRVVSSIMState *s, uint64_t offset,
        uint64_t bytes, QEMUIOVector *qiov, int write)
{
    int ret = 0;
    uint8_t *meta_buf = NULL;
    object *object = NULL;
    obj_id_t obj_loc = {
        .partition_id = 0,
        .object_id = 0};

    if (!qiov->metadata_len)
    {
        ret |= BDRV_BLOCK_ZERO; /* we should define a new value for this case */
        goto exit;
    }

    /* parse metadata */
    meta_buf = g_malloc(qiov->metadata_len);
    qemu_iovec_get_metadata(qiov, meta_buf, qiov->metadata_len);
    if (!parse_metadata(meta_buf, qiov->metadata_len, &obj_loc))
    {
        ret |= BDRV_BLOCK_ZERO; /* we should define a new value for this case */
        goto exit;
    }
    g_free(meta_buf);
    meta_buf = NULL;

    /* Fetch the object from the hashmap */
    if (!(object = get_object(&(s->part), obj_loc, write)))
    {
        ret |= BDRV_BLOCK_DATA; /* we should define a new value for this case */
        goto exit;
    }

    if (write)
        write_to_object(qiov, object, offset, bytes);
    else
        if (!read_from_object(qiov, object, offset, bytes))
        {
            ret |= BDRV_BLOCK_EOF;
            goto exit;
        }

    // Pass rw to simulator
    if (s->simulator)
    {
        if (write)
        {
            if (!lookup_object(obj_loc.object_id))
                _FTL_OBJ_CREATE(obj_loc, bytes);
            _FTL_OBJ_WRITE(obj_loc, offset, bytes);
        }
        else
            _FTL_OBJ_READ(obj_loc, offset, bytes);
    }

    exit:
    if (meta_buf)
        g_free(meta_buf);
    return ret;
}

static int coroutine_fn vssim_co_preadv(BlockDriverState *bs, uint64_t offset,
        uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVVSSIMState *s = bs->opaque;
    trace_vssim_read(bs, offset, bytes);

    if (STORAGE_STRATEGY == 2) /* object strategy */
    {
        return object_prwv(s, offset, bytes, qiov, 0);
    }
    else// if (STORAGE_STRATEGY == 1) /* sector strategy */
    {
        // Read from memory
        qemu_iovec_from_buf(qiov, 0, s->memory + offset, bytes);
        
        // Pass read to simulator
        if (s->simulator) 
            _FTL_READ_SECT(offset / GET_SECTOR_SIZE(), bytes/GET_SECTOR_SIZE());
    }

    return 0;
}

static int coroutine_fn vssim_co_pwritev(BlockDriverState *bs, uint64_t offset,
        uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVVSSIMState *s = bs->opaque;
    trace_vssim_write(bs, offset, bytes);

    if (STORAGE_STRATEGY == 2) /* object strategy */
    {
        return object_prwv(s, offset, bytes, qiov, 1);
    }
    else //if (STORAGE_STRATEGY == 1) /* sector strategy */
    {
        // Write to iovec buffer
        qemu_iovec_to_buf(qiov, 0, s->memory + offset, bytes);
      
        // Pass write to simulator
        if (s->simulator)
            _FTL_WRITE_SECT(offset / GET_SECTOR_SIZE(), bytes/GET_SECTOR_SIZE());
    }
    return 0;
}

static int64_t vssim_getlength(BlockDriverState *bs)
{
    BDRVVSSIMState *s = bs->opaque;
    return s->size;
}

BlockDriver bdrv_vssim = {
    .format_name            = "vssim",
    .instance_size          = sizeof(BDRVVSSIMState),
    .bdrv_open              = vssim_open,
    .bdrv_co_preadv         = vssim_co_preadv,
    .bdrv_co_pwritev        = vssim_co_pwritev,
    .bdrv_close             = vssim_close,
    .bdrv_getlength         = vssim_getlength,
    .bdrv_needs_filename    = false,
    .has_variable_length    = false
};

static void bdrv_vssim_init(void)
{
    bdrv_register(&bdrv_vssim);
}

block_init(bdrv_vssim_init);
