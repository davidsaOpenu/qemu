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

#define NS_MAX 128

static bool g_device_open = false;

typedef struct VSSIMNamespace {

} VSSIMNamespace;

typedef struct BDRVVSSIMState {
    uint64_t allocated_size;
    uint64_t size;
    VSSIMNamespace *allocated[NS_MAX];
    BdrvNamespace *namespaces[NS_MAX];
    bool simulator;
} BDRVVSSIMState;

typedef struct BDRVVSSIMNSState {
    char * memory;
    uint32_t nsid;
    uint64_t size;
    bool simulator;
} BDRVVSSIMNSState;

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

static int vssim_ns_open(BlockDriverState *bs, QDict * dict, int flags,
                      Error **errp)
{
    BDRVVSSIMNSState *s = bs->opaque;
    QemuOpts *opts = NULL;
    trace_vssim_open(bs);

    printf("ns opened\n");

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, dict, &error_abort);

    s->size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE, 0);
    s->simulator = qemu_opt_get_bool(opts, VSSIM_BLOCK_OPT_SIMULATOR, true);
    qemu_opts_del(opts);

    // Allocate the memory
    s->memory = qemu_blockalign0(bs, s->size);

    // trace_vssim_initialized(bs, s->size);

    return 0;
}

static void vssim_ns_close(BlockDriverState *bs)
{
    BDRVVSSIMNSState *s = bs->opaque;
    // trace_vssim_close(bs);

    printf("ns closing\n");

    // Clear memory
    if (NULL != s->memory) {
        qemu_vfree(s->memory);
    }
}

static int coroutine_fn vssim_ns_co_preadv(BlockDriverState *bs, uint64_t offset,
        uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVVSSIMNSState *s = bs->opaque;
    trace_vssim_read(bs, offset, bytes);

    // Read from memory
    qemu_iovec_from_buf(qiov, 0, s->memory + offset, bytes);

    // Pass write to simulator
    if (s->simulator) {
        _FTL_READ_SECT(offset / GET_SECTOR_SIZE(), bytes/GET_SECTOR_SIZE());
    }

    return 0;
}

static int coroutine_fn vssim_ns_co_pwritev(BlockDriverState *bs, uint64_t offset,
        uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVVSSIMNSState *s = bs->opaque;
    trace_vssim_write(bs, offset, bytes);

    // Write to iovec buffer
    qemu_iovec_to_buf(qiov, 0, s->memory + offset, bytes);

    // Pass write to simulator
    if (s->simulator) {
        _FTL_WRITE_SECT(offset / GET_SECTOR_SIZE(), bytes/GET_SECTOR_SIZE());
    }

    return 0;
}

static int64_t vssim_ns_getlength(BlockDriverState *bs)
{
    BDRVVSSIMState *s = bs->opaque;
    return s->size;
}

BlockDriver bdrv_ns_vssim = {
    .format_name            = "vssim-ns",
    .instance_size          = sizeof(BDRVVSSIMNSState),
    .bdrv_open              = vssim_ns_open,
    .bdrv_co_preadv         = vssim_ns_co_preadv,
    .bdrv_co_pwritev        = vssim_ns_co_pwritev,
    .bdrv_close             = vssim_ns_close,
    .bdrv_getlength         = vssim_ns_getlength,
    .bdrv_needs_filename    = false,
    .has_variable_length    = false
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

    // Initialize FTL and logger
    if (s->simulator) {
        FTL_INIT();
        INIT_LOG_MANAGER();
    }

    trace_vssim_initialized(bs, s->size);

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

    // // Clear memory
    // if (NULL != s->memory) {
    //     qemu_vfree(s->memory);
    // }

    // Clear singleton state
    g_device_open = false;
}

static int vssim_ns_create(BlockDriverState *bs, uint64_t nsze, uint32_t *nsid)
{
    BDRVVSSIMState *s = bs->opaque;
    BlockDriverState *ret = NULL;
    Error *local_error = NULL;
    uint32_t i = 0;

    if (nsze > s->size - s->allocated_size)
        return -ENOSPC;

    while (s->allocated[i]) {
        i++;
    }

    if (i == NS_MAX)
        return -ENOMEM;

    s->allocated[i] = g_new0(sizeof(VSSIMNamespace));
    *nsid = i+1;

    return 0;
}

static int vssim_ns_delete(BlockDriverState *bs, uint32_t nsid)
{
    BDRVVSSIMState *s = bs->opaque;
    BlockDriverState *ret = NULL;

    if (nsid > NS_MAX || !s->allocated[nsid-1])
        return -ENOENT;

    g_free(s->allocated[nsid-1]);
    s->allocated[nsid-1] = NULL;

    return 0;
}

int vssim_ns_attach(BlockDriverState *bs, uint32_t nsid)
{
    BDRVVSSIMState *s = bs->opaque;
    BlockBackend *blk;
    BdrvNamespace *ns;
    Error *local_error = NULL;

    if (nsid > NS_MAX || !s->allocated[nsid-1])
        return -ENOENT;

    if (s->namespaces[nsid-1])
        return -EEXIST;

    QDict *opts = qdict_new();
    qdict_put_str(opts, "driver", "vssim-ns");
    qdict_put_int(opts, BLOCK_OPT_SIZE, nsze);
    qdict_put_bool(opts, VSSIM_BLOCK_OPT_SIMULATOR, s->simulator);
    blk = blk_new_open(NULL, NULL, opts, 0, &local_error);
    ns = g_new0(sizeof(BdrvNamespace));
    ns->opaque = blk;

    s->namespaces[nsid-1] = ns;

    return 0;
}

static int vssim_ns_detach(BlockDriverState *bs, uint64_t nsze, uint32_t *nsid)
{
    BDRVVSSIMState *s = bs->opaque;
    BlockDriverState *ret = NULL;
    Error *local_error = NULL;

    if (nsid > NS_MAX || !s->allocated[nsid-1])
        return -ENOENT;

    if (!s->namespaces[nsid-1])
        return -ENODEV;

    bdrv_close(s->namespaces[nsid-1]);
    s->namespaces[nsid-1] = NULL;

    return ret;
}

static BdrvNamesapce *vssim_ns_get(BlockDriverState *bs, uint32_t nsid)
{
    BDRVVSSIMState *s = bs->opaque;
    BlockDriverState *ret = NULL;
    Error *local_error = NULL;

    if (nsid > NS_MAX)
        return NULL;

    return s->namespaces[nsid];
}

BlockDriver bdrv_vssim = {
    .format_name            = "vssim",
    .instance_size          = sizeof(BDRVVSSIMState),
    .bdrv_open              = vssim_open,
    // .bdrv_co_preadv         = vssim_co_preadv,
    // .bdrv_co_pwritev        = vssim_co_pwritev,
    .bdrv_close             = vssim_close,
    // .bdrv_getlength         = vssim_getlength,
    .bdrv_ns_create         = vssim_ns_create,
    .bdrv_ns_delete         = vssim_ns_delete,
    .bdrv_ns_attach         = vssim_ns_attach,
    .bdrv_ns_detach         = vssim_ns_detach,
    .bdrv_ns_get            = vssim_ns_get,
    .bdrv_needs_filename    = false,
    .has_variable_length    = false
};

static void bdrv_vssim_init(void)
{
    // _FTL_LOAD_NS();
    bdrv_register(&bdrv_vssim);
    bdrv_register(&bdrv_ns_vssim);
}

block_init(bdrv_vssim_init);
