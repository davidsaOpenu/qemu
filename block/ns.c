#include "qemu/osdep.h"
#include "block/block_int.h"
#include <stdint.h>

int bdrv_ns_create(BlockDriverState *bs, uint64_t size, uint32_t *nsid) {
    BlockDriver *drv = bs->drv;
    int ret = -ENOSYS;

    if (drv->bdrv_ns_create)
        ret = drv->bdrv_ns_create(bs, size, nsid);

    return ret;
}

int bdrv_ns_delete(BlockDriverState *bs, uint32_t nsid) {
    BlockDriver *drv = bs->drv;
    int ret = -ENOSYS;

    if (drv->bdrv_ns_delete)
        ret = drv->bdrv_ns_delete(bs, nsid);

    return ret;
}

int bdrv_ns_attach(BlockDriverState *bs, uint32_t nsid) {
    BlockDriver *drv = bs->drv;
    int ret = -ENOSYS;

    if (drv->bdrv_ns_attach)
        ret = drv->bdrv_ns_attach(bs, nsid);

    return ret;
}

int bdrv_ns_detach(BlockDriverState *bs, uint32_t nsid) {
    BlockDriver *drv = bs->drv;
    int ret = -ENOSYS;

    if (drv->bdrv_ns_detach)
        ret = drv->bdrv_ns_detach(bs, nsid);

    return ret;
}

BdrvNamespace *bdrv_ns_get(BlockDriverState *bs, uint32_t nsid) {
    BlockDriver *drv = bs->drv;
    BdrvNamespace *ns = NULL;

    if (drv->bdrv_ns_detach)
        ns = drv->bdrv_ns_get(bs, nsid);

    return ns;
}
