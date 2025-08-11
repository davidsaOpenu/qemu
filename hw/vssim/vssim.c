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

static bool g_ftl_initialized = false;
static int g_device_count = 0;

typedef struct BDRVVSSIMState {
    char * memory;
    uint64_t size;
    bool simulator;
    uint32_t nsid;
    uint8_t device_index;
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

static uint8_t vssim_get_device_index_from_serial(BlockDriverState *bs) {
    // Try to get serial from device name or use default
    const char *serial = bs->device_name ? bs->device_name : "1";

    int serial_num = atoi(serial);
    int index = serial_num - 1;  // Convert 1,2,3... to 0,1,2...

    return (index >= 0 && index < MAX_DEVICES) ? index : 0;
}

static int vssim_open(BlockDriverState *bs, QDict * dict, int flags,
                      Error **errp)
{
    BDRVVSSIMState *s = bs->opaque;
    QemuOpts *opts = NULL;
    ssd_config_t *devices = NULL;

    trace_vssim_open(bs);

    // Prase the drive options
    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, dict, &error_abort);
    s->size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE,
                                VSSIM_DEFAULT_FILE_SIZE_IN_BYTES);
    s->simulator = qemu_opt_get_bool(opts, VSSIM_BLOCK_OPT_SIMULATOR, true);
    qemu_opts_del(opts);

    // TODO: Set the namespace ID.
    s->nsid = 0;
    if (s->simulator) {
        if (!g_ftl_initialized) {
            INIT_SSD_CONFIG();
            g_ftl_initialized = true;
        }

        // Get device index for this BlockDriverState
        s->device_index = vssim_get_device_index_from_serial(bs);

        // Validate device index
        devices = GET_DEVICES();
        if (s->device_index >= device_count) {
            error_setg(errp, "VSSIM device index %d exceeds configured devices (%d)",
                       s->device_index, device_count);
            return -EINVAL;
        }

        // Override size from device configuration
        ssd_config_t *device = &devices[s->device_index];
        s->size = (uint64_t)device->flash_nb * device->block_nb *
                  device->page_nb * device->page_size;

        // Initialize FTL for this specific device
        FTL_INIT_DEVICE(s->device_index);
        INIT_LOG_MANAGER_DEVICE(s->device_index);
    }

    // Allocate the memory
    s->memory = qemu_blockalign0(bs, s->size);

    g_device_count++;
    trace_vssim_initialized(bs, s->size, s->memory);

    return 0;
}

static void vssim_close(BlockDriverState *bs)
{
    BDRVVSSIMState *s = bs->opaque;
    trace_vssim_close(bs);

    // Destruct FTL for this device
    if (s->simulator) {
        TERM_LOG_MANAGER(s->device_index);
        FTL_TERM(s->device_index);
    }

    // Clear memory
    if (NULL != s->memory) {
        qemu_vfree(s->memory);
    }

    g_device_count--;

    // Clean up global state when all devices are closed
    if (g_device_count == 0 && g_ftl_initialized) {
        g_ftl_initialized = false;
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
        _FTL_READ_SECT(s->device_index,
                        s->nsid,
                        offset / GET_SECTOR_SIZE(s->device_index),
                        bytes / GET_SECTOR_SIZE(s->device_index), NULL);
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
        _FTL_WRITE_SECT(s->device_index,
                        s->nsid,
                        offset / GET_SECTOR_SIZE(s->device_index),
                        bytes / GET_SECTOR_SIZE(s->device_index), NULL);
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
