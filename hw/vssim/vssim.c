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

#define VSSIM_FILE_EXTENSION                  (".vssim")
#define VSSIM_FILE_EXTENSION_CHARACTER_LENGTH (sizeof(VSSIM_FILE_EXTENSION)-1)

#define VSSIM_DEFAULT_FILE_SIZE_IN_BYTES      (1024*1024*256)

#define VSSIM_BLOCK_OPT_SIMULATOR             ("simulator")

static bool g_device_open = false;

typedef struct BDRVVSSIMState {
    char * memory;
    uint64_t size;
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

    // Allocate the memory
    s->memory = qemu_blockalign0(bs, s->size);

    // Initialize FTL and logger
    if (s->simulator) {
        FTL_INIT();
        INIT_LOG_MANAGER();
    }

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
    }

    // Clear memory
    if (NULL != s->memory) {
        qemu_vfree(s->memory);
    }

    // Clear singleton state
    g_device_open = false;
}

<<<<<<< PATCH SET (164aeb Integrate FTL and osd API into QEMU nvme module)
/**
 * Object private read & write function.
 *
 * use write to distinguise between read & write mode (0 = read, non-zero = write).
 * qiov should hold the metadata info (used to find the object info)
 */
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
        ret |= BDRV_BLOCK_ZERO; /* TODO: define a new value for this case */
        goto exit;
    }

    /* parse metadata */
    meta_buf = g_malloc(qiov->metadata_len);
    qemu_iovec_get_metadata(qiov, meta_buf, qiov->metadata_len);
    if (!parse_metadata(meta_buf, qiov->metadata_len, &obj_loc))
    {
        ret |= BDRV_BLOCK_ZERO; /* TODO: define a new value for this case */
        goto exit;
    }
    g_free(meta_buf);
    meta_buf = NULL;

    /* Fetch the object from the hashmap */
    if (!(object = get_object(&(s->part), obj_loc, write)))
    {
        ret |= BDRV_BLOCK_DATA; /* TODO: define a new value for this case */
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
    /* implementation is deprecated
    if (s->simulator)
    {
        if (write)
        {
            if (!lookup_object(obj_loc.object_id))
                _FTL_OBJ_CREATE(obj_loc, bytes);
            _FTL_OBJ_WRITE(obj_loc, offset, bytes);
        }
        else
        {
            _FTL_OBJ_READ(obj_loc, offset, bytes);
        }
    }
    */

    exit:
    if (meta_buf)
        g_free(meta_buf);
    return ret;
}

=======
>>>>>>> BASE      (4810ec Revert "Added object strategy to the new qemu")
static int coroutine_fn vssim_co_preadv(BlockDriverState *bs, uint64_t offset,
        uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVVSSIMState *s = bs->opaque;
    trace_vssim_read(bs, offset, bytes);

    // Read from memory
    qemu_iovec_from_buf(qiov, 0, s->memory + offset, bytes);

    // Pass write to simulator
    if (s->simulator) {
        _FTL_READ_SECT(offset / GET_SECTOR_SIZE(), bytes/GET_SECTOR_SIZE());
    }

    return 0;
}

static int coroutine_fn vssim_co_pwritev(BlockDriverState *bs, uint64_t offset,
        uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVVSSIMState *s = bs->opaque;
    trace_vssim_write(bs, offset, bytes);

    // Write to iovec buffer
    qemu_iovec_to_buf(qiov, 0, s->memory + offset, bytes);

    // Pass write to simulator
    if (s->simulator) {
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
