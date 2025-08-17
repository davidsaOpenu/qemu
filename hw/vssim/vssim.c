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

static uint32_t g_devices_open = 0;

typedef struct BDRVVSSIMState {
    char * memory;
    uint64_t size;
    bool simulator;
    uint32_t nsid;
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
        {
            .name = "nsid",
            .type = QEMU_OPT_NUMBER,
            .help = "nsid"
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

    // Prase the drive options
    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, dict, &error_abort);
    s->simulator = qemu_opt_get_bool(opts, VSSIM_BLOCK_OPT_SIMULATOR, true);
    s->nsid = qemu_opt_get_number(opts, "nsid", 0);
    if (s->nsid == 0) {
        s->size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE,
                                    VSSIM_DEFAULT_FILE_SIZE_IN_BYTES);
    } else {
        s->size = FTL_GET_NAMESPACE_SIZE(s->nsid) * GET_PAGE_SIZE();
        s->memory = qemu_blockalign0(bs, s->size);
    }

    qemu_opts_del(opts);

    if (g_devices_open == 0 && s->simulator) {
        FTL_INIT();
        INIT_LOG_MANAGER();
    }

    g_devices_open++;

    // Initialize FTL and logger
    trace_vssim_initialized(bs, s->size, s->memory);

    return 0;
}

static void vssim_close(BlockDriverState *bs)
{
    BDRVVSSIMState *s = bs->opaque;
    trace_vssim_close(bs);

    g_devices_open--;

    // Destruct FTL
    if (g_devices_open == 0 && s->simulator) {
        TERM_LOG_MANAGER();
        FTL_TERM();
    }

    // Clear memory
    if (NULL != s->memory) {
        qemu_vfree(s->memory);
    }
}

static int coroutine_fn vssim_co_preadv(BlockDriverState *bs, uint64_t offset,
        uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVVSSIMState *s = bs->opaque;
    trace_vssim_read(bs, offset, bytes);

    // Read from memory
    qemu_iovec_from_buf(qiov, 0, s->memory + offset, bytes);

    // Pass write to simulator
    if (s->simulator) {
        _FTL_READ_SECT(s->nsid, offset / GET_SECTOR_SIZE(), bytes/GET_SECTOR_SIZE(), NULL);
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
        _FTL_WRITE_SECT(s->nsid, offset / GET_SECTOR_SIZE(), bytes/GET_SECTOR_SIZE(), NULL);
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
