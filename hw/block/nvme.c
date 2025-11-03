/*
 * QEMU NVM Express Controller
 *
 * Copyright (c) 2012, Intel Corporation
 *
 * Written by Keith Busch <keith.busch@intel.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

/**
 * Reference Specs: http://www.nvmexpress.org, 1.2, 1.1, 1.0e
 *
 *  http://www.nvmexpress.org/resources/
 */

/**
 * Usage: add options:
 *      -drive file=<file>,if=none,id=<drive_id>
 *      -device nvme,drive=<drive_id>,serial=<serial>,id=<id[optional]>, \
 *              cmb_size_mb=<cmb_size_mb[optional]>
 *
 * Note cmb_size_mb denotes size of CMB in MB. CMB is assumed to be at
 * offset 0 in BAR2 and supports only WDS, RDS and SQS for now.
 */


#include "qemu/osdep.h"
#include "qemu/range.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "hw/pci/msix.h"
#include "hw/pci/pci.h"
#include "sysemu/sysemu.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "sysemu/block-backend.h"

#include "hw/vssim/simulator/ftl_obj_strategy.h"
#include "hw/vssim/simulator/osc-osd/osd-util/osd-defs.h"
#include "hw/vssim/simulator/osc-osd/osd-util/osd-util.h"

#include "qemu/log.h"
#include "trace.h"
#include "../vssim/vssim.h"
#include "nvme.h"


#define OSD_LIST_BUFFER_SIZE        (1024)
#define OSD_LIST_VALUES_OFFSET      (24)
#define OSD_KEY_SIZE                (8)
#define NVMECLI_KEY_SIZE            (16)
#define NVMECLI_KEY_PADDED          (20)

#define PCI_EXP_LNKCAP_AOC 0x00400000 /* ASPM Optionality Compliance (AOC) */
#define PCI_EXP_DEVCAP2_CTDS 0x10 /* Completion Timeout Disable Supported (CTDS) */

#define INVALID_DEVICE_INDEX 0xFF

#define NVME_GUEST_ERR(trace, fmt, ...) \
    do { \
        (trace_##trace)(__VA_ARGS__); \
        qemu_log_mask(LOG_GUEST_ERROR, #trace \
            " in %s: " fmt "\n", __func__, ## __VA_ARGS__); \
    } while (0)

static uint8_t get_device_index(NvmeCtrl* ctrl);

static void nvme_process_sq(void *opaque);

static uint16_t nvme_ftl_delete(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
static uint16_t nvme_ftl_retreive(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
static uint16_t nvme_ftl_store(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
static uint16_t nvme_ftl_list(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
static uint16_t nvme_ftl_exist(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);

static void nvme_addr_read(NvmeCtrl *n, hwaddr addr, void *buf, int size)
{
    if (n->cmbsz && addr >= n->ctrl_mem.addr &&
                addr < (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size))) {
        memcpy(buf, (void *)&n->cmbuf[addr - n->ctrl_mem.addr], size);
    } else {
        pci_dma_read(&n->parent_obj, addr, buf, size);
    }
}

static int nvme_valid_sqid(NvmeCtrl *n, uint16_t sqid)
{
    return sqid < n->num_queues;
}

static int nvme_used_sqid(NvmeCtrl *n, uint16_t sqid)
{
    return sqid < n->num_queues && n->sq[sqid] != NULL ? 1 : 0;
}

static int nvme_valid_cqid(NvmeCtrl *n, uint16_t cqid)
{
    return cqid < n->num_queues;
}

static int nvme_used_cqid(NvmeCtrl *n, uint16_t cqid)
{
    return cqid < n->num_queues && n->cq[cqid] != NULL ? 1 : 0;
}

static void nvme_inc_cq_tail(NvmeCQueue *cq)
{
    cq->tail++;
    if (cq->tail >= cq->size) {
        cq->tail = 0;
        cq->phase = !cq->phase;
    }
}

static void nvme_inc_sq_head(NvmeSQueue *sq)
{
    sq->head = (sq->head + 1) % sq->size;
}

static uint8_t nvme_cq_full(NvmeCQueue *cq)
{
    return (cq->tail + 1) % cq->size == cq->head;
}

static uint8_t nvme_sq_empty(NvmeSQueue *sq)
{
    return sq->head == sq->tail;
}

static void nvme_irq_check(NvmeCtrl *n)
{
    if (msix_enabled(&(n->parent_obj))) {
        return;
    }
    if (~n->bar.intms & n->irq_status) {
        pci_irq_assert(&n->parent_obj);
    } else {
        pci_irq_deassert(&n->parent_obj);
    }
}

static void nvme_irq_assert(NvmeCtrl *n, NvmeCQueue *cq)
{
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            trace_nvme_irq_msix(cq->vector);
            msix_notify(&(n->parent_obj), cq->vector);
        } else {
            trace_nvme_irq_pin();
            assert(cq->cqid < 64);
            n->irq_status |= 1 << cq->cqid;
            nvme_irq_check(n);
        }
    } else {
        trace_nvme_irq_masked();
    }
}

static void nvme_irq_deassert(NvmeCtrl *n, NvmeCQueue *cq)
{
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            return;
        } else {
            assert(cq->cqid < 64);
            n->irq_status &= ~(1 << cq->cqid);
            nvme_irq_check(n);
        }
    }
}

static uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov, uint64_t prp1,
                             uint64_t prp2, uint32_t len, NvmeCtrl *n)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;

    if (unlikely(!prp1)) {
        trace_nvme_err_invalid_prp();
        return NVME_INVALID_FIELD | NVME_DNR;
    } else if (n->cmbsz && prp1 >= n->ctrl_mem.addr &&
               prp1 < n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) {
        qsg->nsg = 0;
        qemu_iovec_init(iov, num_prps);
        qemu_iovec_add(iov, (void *)&n->cmbuf[prp1 - n->ctrl_mem.addr], trans_len);
    } else {
        pci_dma_sglist_init(qsg, &n->parent_obj, num_prps);
        qemu_sglist_add(qsg, prp1, trans_len);
    }
    len -= trans_len;
    if (len) {
        if (unlikely(!prp2)) {
            trace_nvme_err_invalid_prp2_missing();
            goto unmap;
        }
        if (len > n->page_size) {
            uint64_t prp_list[n->max_prp_ents];
            uint32_t nents, prp_trans;
            int i = 0;

            nents = (len + n->page_size - 1) >> n->page_bits;
            prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
            nvme_addr_read(n, prp2, (void *)prp_list, prp_trans);
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == n->max_prp_ents - 1 && len > n->page_size) {
                    if (unlikely(!prp_ent || prp_ent & (n->page_size - 1))) {
                        trace_nvme_err_invalid_prplist_ent(prp_ent);
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
                    nvme_addr_read(n, prp_ent, (void *)prp_list,
                        prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (unlikely(!prp_ent || prp_ent & (n->page_size - 1))) {
                    trace_nvme_err_invalid_prplist_ent(prp_ent);
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                if (qsg->nsg){
                    qemu_sglist_add(qsg, prp_ent, trans_len);
                } else {
                    qemu_iovec_add(iov, (void *)&n->cmbuf[prp_ent - n->ctrl_mem.addr], trans_len);
                }
                len -= trans_len;
                i++;
            }
        } else {
            if (unlikely(prp2 & (n->page_size - 1))) {
                trace_nvme_err_invalid_prp2_align(prp2);
                goto unmap;
            }
            if (qsg->nsg) {
                qemu_sglist_add(qsg, prp2, len);
            } else {
                qemu_iovec_add(iov, (void *)&n->cmbuf[prp2 - n->ctrl_mem.addr], trans_len);
            }
        }
    }
    return NVME_SUCCESS;

 unmap:
    qemu_sglist_destroy(qsg);
    return NVME_INVALID_FIELD | NVME_DNR;
}

static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = NVME_SUCCESS;

    trace_nvme_dma_read(prp1, prp2);

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qsg.nsg > 0) {
        if (unlikely(dma_buf_read(ptr, len, &qsg))) {
            trace_nvme_err_invalid_dma();
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_sglist_destroy(&qsg);
    } else {
        if (unlikely(qemu_iovec_to_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_iovec_destroy(&iov);
    }
    return status;
}

static uint16_t nvme_dma_write_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = NVME_SUCCESS;

    trace_nvme_dma_read(prp1, prp2);

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qsg.nsg > 0) {
        if (unlikely(dma_buf_write(ptr, len, &qsg))) {
            trace_nvme_err_invalid_dma();
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_sglist_destroy(&qsg);
    } else {
        if (unlikely(qemu_iovec_from_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_iovec_destroy(&iov);
    }
    return status;
}

static void nvme_post_cqes(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeCtrl *n = cq->ctrl;
    NvmeRequest *req, *next;

    // Fast path if nothing to be processed
    if (QTAILQ_EMPTY(&cq->req_list)) {
        return;
    }

    QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
        NvmeSQueue *sq;
        hwaddr addr;

        if (nvme_cq_full(cq)) {
            break;
        }

        QTAILQ_REMOVE(&cq->req_list, req, entry);
        sq = req->sq;
        req->cqe.status = cpu_to_le16((req->status << 1) | cq->phase);
        req->cqe.sq_id = cpu_to_le16(sq->sqid);
        req->cqe.sq_head = cpu_to_le16(sq->head);
        addr = cq->dma_addr + cq->tail * n->cqe_size;
        nvme_inc_cq_tail(cq);
        pci_dma_write(&n->parent_obj, addr, (void *)&req->cqe,
            sizeof(req->cqe));
        QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
    }
    nvme_irq_assert(n, cq);
}

/**
 * Asynchronous event proccessing
 *
 * this function is the bare bone of the async-event system,
 * every event is added to the event_queue and pulled from here once there
 * is an async request for an event (adm_cmd_async_ev_req).
 */
static void nvme_async_req(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeCtrl *n = cq->ctrl;
    NvmeRequest *req, *req_next;

    // Fast path if nothing to be processed
    if (QTAILQ_EMPTY(&cq->async_req_list)) {
        return;
    }

    QTAILQ_FOREACH_SAFE(req, &cq->async_req_list, entry, req_next) {
        NvmeSQueue *sq;
        hwaddr addr;
        AsyncResult *result;
        AsyncEvent *event, *event_next;

        if (nvme_cq_full(cq)) {
            break;
        }

        // No events!
        if (QTAILQ_EMPTY(&cq->event_queue)) {
            break;
        }

        QTAILQ_REMOVE(&cq->async_req_list, req, entry);

        // TODO: Implement an efficient function to pop an event from the queue
        QTAILQ_FOREACH_SAFE(event, &cq->event_queue, entry, event_next) {
            QTAILQ_REMOVE(&cq->event_queue, event, entry);
            break;
        }

        result = (AsyncResult *)&req->cqe.result;
        result->event_type = event->result.event_type;
        result->event_info = event->result.event_info;
        result->log_page   = event->result.log_page;
        g_free(event);

        cq->outstanding_asyncs--;
        sq = req->sq;
        req->cqe.status = cpu_to_le16((req->status << 1) | cq->phase);
        req->cqe.sq_id = cpu_to_le16(sq->sqid);
        req->cqe.sq_head = cpu_to_le16(sq->head);
        addr = cq->dma_addr + cq->tail * n->cqe_size;
        nvme_inc_cq_tail(cq);
        pci_dma_write(&n->parent_obj, addr, (void *)&req->cqe,
            sizeof(req->cqe));
        QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
    }
    msix_notify(&(n->parent_obj), 0);
}

/**
 * This function is used to generate a new event (and adds it to the event_queue)
 */
static void enqueue_async_event(NvmeCtrl *n, uint8_t event_type, uint8_t event_info, uint8_t log_page)
{
    AsyncEvent *event = (AsyncEvent *)g_malloc(sizeof(AsyncEvent));

    event->result.event_type = event_type;
    event->result.event_info = event_info;
    event->result.log_page   = log_page;

    QTAILQ_INSERT_TAIL(&(n->admin_cq.event_queue), event, entry);

    timer_mod(n->admin_cq.async_req_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 20000);
}

static void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req)
{
    assert(cq->cqid == req->sq->cqid);
    QTAILQ_REMOVE(&req->sq->out_req_list, req, entry);
    QTAILQ_INSERT_TAIL(&cq->req_list, req, entry);
    timer_mod(cq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
}

static void nvme_rw_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    if (!ret) {
        block_acct_done(blk_get_stats(n->conf.blk), &req->acct);
        req->status = NVME_SUCCESS;
    } else {
        block_acct_failed(blk_get_stats(n->conf.blk), &req->acct);
        req->status = NVME_INTERNAL_DEV_ERROR;
    }
    if (req->has_sg) {
        qemu_sglist_destroy(&req->qsg);
    }
    nvme_enqueue_req_completion(cq, req);
}

static uint16_t nvme_flush(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    req->has_sg = false;
    block_acct_start(blk_get_stats(n->conf.blk), &req->acct, 0,
         BLOCK_ACCT_FLUSH);
    req->aiocb = blk_aio_flush(n->conf.blk, nvme_rw_cb, req);

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_write_zeros(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t aio_slba = slba << (data_shift - BDRV_SECTOR_BITS);
    uint32_t aio_nlb = nlb << (data_shift - BDRV_SECTOR_BITS);

    if (unlikely(slba + nlb > ns->id_ns.nsze)) {
        trace_nvme_err_invalid_lba_range(slba, nlb, ns->id_ns.nsze);
        return NVME_LBA_RANGE | NVME_DNR;
    }

    req->has_sg = false;
    block_acct_start(blk_get_stats(n->conf.blk), &req->acct, 0,
                     BLOCK_ACCT_WRITE);
    req->aiocb = blk_aio_pwrite_zeroes(n->conf.blk, aio_slba, aio_nlb,
                                        BDRV_REQ_MAY_UNMAP, nvme_rw_cb, req);
    return NVME_NO_COMPLETE;
}

static uint16_t nvme_rw(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint32_t nlb  = le32_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);

    uint8_t lba_index  = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t data_size = (uint64_t)nlb << data_shift;
    uint64_t data_offset = slba << data_shift;
    int is_write = rw->opcode == NVME_CMD_WRITE ? 1 : 0;
    enum BlockAcctType acct = is_write ? BLOCK_ACCT_WRITE : BLOCK_ACCT_READ;

    trace_nvme_rw(is_write ? "write" : "read", nlb, data_size, slba);

    if (unlikely((slba + nlb) > ns->id_ns.nsze)) {
        block_acct_invalid(blk_get_stats(n->conf.blk), acct);
        trace_nvme_err_invalid_lba_range(slba, nlb, ns->id_ns.nsze);
        return NVME_LBA_RANGE | NVME_DNR;
    }

    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
        block_acct_invalid(blk_get_stats(n->conf.blk), acct);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    dma_acct_start(n->conf.blk, &req->acct, &req->qsg, acct);
    if (req->qsg.nsg > 0) {
        req->has_sg = true;
        req->aiocb = is_write ?
            dma_blk_write(n->conf.blk, &req->qsg, data_offset, BDRV_SECTOR_SIZE,
                          nvme_rw_cb, req) :
            dma_blk_read(n->conf.blk, &req->qsg, data_offset, BDRV_SECTOR_SIZE,
                         nvme_rw_cb, req);
    } else {
        req->has_sg = false;
        req->aiocb = is_write ?
            blk_aio_pwritev(n->conf.blk, data_offset, &req->iov, 0, nvme_rw_cb,
                            req) :
            blk_aio_preadv(n->conf.blk, data_offset, &req->iov, 0, nvme_rw_cb,
                           req);
    }

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_nvm_io_cmd(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_CMD_FLUSH:
        return nvme_flush(n, ns, cmd, req);
    case NVME_CMD_WRITE_ZEROS:
        return nvme_write_zeros(n, ns, cmd, req);
    case NVME_CMD_WRITE:
    case NVME_CMD_READ:
        return nvme_rw(n, ns, cmd, req);
    default:
        trace_nvme_err_invalid_opc(cmd->opcode);
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static uint16_t nvme_ftl_store(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeKvCmd *kv_cmd = (NvmeKvCmd *)cmd;
    uint16_t status;
    uint8_t device_index = get_device_index(n);
    if (INVALID_DEVICE_INDEX == device_index)
    {
        printf("Failed to get device index\n");
        return NVME_FTL_API_FAILED;
    }

    if (kv_cmd->key_low > UINT64_MAX - USEROBJECT_OID_LB) {
        printf("Overflow detected while calculating the object id!\n");
        return NVME_INVALID_KEY;
        // TODO: after fixing issue with kv_cmd->key_high, we
        // should reconsider this if condition.
    }

    uint8_t *data = NULL;

    // Dummy pointer, for empty files.
    uint8_t dummy = 0;
    uint32_t value_size = kv_cmd->value_size;
    if (value_size > 0) {
        data = g_malloc0(value_size);
        status = nvme_dma_write_prp(n, data, value_size, kv_cmd->prp1, kv_cmd->prp2);
        if (unlikely(status != NVME_SUCCESS)) {
            printf("Failed write %d\n", (int)status);
            g_free(data);
            return status;
        }
    } else {
        data = &dummy;
    }

    // Store the value using the FTL API and OSD target API

    // TODO: fix issue with kv_cmd->key_high
    obj_id_t object = {
        .object_id = USEROBJECT_OID_LB + kv_cmd->key_low,
        .partition_id = PARTITION_PID_LB
    };

    ftl_ret_val ftl_ret = 0;
    if (!lookup_object(device_index, object.object_id)) {
        ftl_ret = FTL_OBJ_CREATE(device_index, object, value_size);
        if (ftl_ret != FTL_SUCCESS) {
            if (value_size > 0) g_free(data);
            printf("Failed to create object\n");
            return NVME_FTL_API_FAILED;
        }
    }

    if (value_size > 0) {
        ftl_ret = FTL_OBJ_WRITE(device_index, object, data, 0 /* offest */, value_size);
        g_free(data);
        if (ftl_ret != FTL_SUCCESS) {
            printf("Failed to write object using FTP API.\n");
            return NVME_FTL_API_FAILED;
        }
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_ftl_retreive(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeKvCmd *kv_cmd = (NvmeKvCmd *)cmd;
    uint16_t status;
    uint8_t device_index = get_device_index(n);
    if (INVALID_DEVICE_INDEX == device_index)
    {
        printf("Failed to get device index\n");
        return NVME_FTL_API_FAILED;
    }

    // Retreive the value using the FTL API and OSD target API

    if (kv_cmd->key_low > UINT64_MAX - USEROBJECT_OID_LB) {
        printf("Overflow detected while calculating the object id!\n");
        return NVME_INVALID_KEY;
        // TODO: after fixing issue with kv_cmd->key_high, we
        // should reconsider this if condition.
    }

    // TODO: fix issue with kv_cmd->key_high
    obj_id_t object = {
        .object_id = USEROBJECT_OID_LB + kv_cmd->key_low,
        .partition_id = PARTITION_PID_LB
    };

    stored_object *found_object = lookup_object(device_index, object.object_id);
    if (!found_object) {
        printf("failed to find object using FTL call.\n");
        return NVME_FTL_API_FAILED;
    }

    if (kv_cmd->offset > found_object->size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    uint32_t read_size = kv_cmd->value_size + 1;
    void *data = g_malloc0(read_size + 1);
    if (!data) {
        printf("Allocation failed.\n");
        return NVME_SYSTEM_ERROR;
    }

    ftl_ret_val ftl_ret = FTL_OBJ_READ(device_index, object, data, 0 /* offest */, &read_size);
    if (ftl_ret != FTL_SUCCESS) {
        g_free(data);
        printf("Failed to read object using FTP API.\n");
        return NVME_FTL_API_FAILED;
    }

    if (read_size > 0) {
        status = nvme_dma_read_prp(n, data + kv_cmd->offset, read_size, kv_cmd->prp1, kv_cmd->prp2);
        if (unlikely(status != NVME_SUCCESS)) {
            g_free(data);
            printf("Failed read %d\n", (int)status);
            return status;
        }
    }

    req->cqe.result = read_size;

    g_free(data);

    return NVME_SUCCESS;
}

static uint16_t nvme_ftl_delete(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeKvCmd *kv_cmd = (NvmeKvCmd *)cmd;

    if (kv_cmd->key_low > UINT64_MAX - USEROBJECT_OID_LB) {
        printf("Overflow detected while calculating the object id!\n");
        return NVME_INVALID_KEY;
        // TODO: after fixing issue with kv_cmd->key_high, we
        // should reconsider this if condition.
    }

    // TODO: fix issue with kv_cmd->key_high
    obj_id_t object = {
        .object_id = USEROBJECT_OID_LB + kv_cmd->key_low,
        .partition_id = PARTITION_PID_LB
    };

    uint8_t device_index = get_device_index(n);
    if (INVALID_DEVICE_INDEX == device_index)
    {
        printf("Failed to get device index\n");
        return NVME_FTL_API_FAILED;
    }

    FTL_OBJ_DELETE(device_index, object);

    return NVME_SUCCESS;
}

static uint16_t nvme_ftl_list(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeKvCmd *kv_cmd = (NvmeKvCmd *)cmd;
    uint8_t device_index = get_device_index(n);
    if (INVALID_DEVICE_INDEX == device_index)
    {
        printf("Failed to get device index\n");
        return NVME_FTL_API_FAILED;
    }

    // First, calculate the required buffer size
    if (kv_cmd->value_size < sizeof(uint32_t)) {
        printf("Invalid size, must be at least 4\n");
        return NVME_KEY_DOES_NOT_EXIST | NVME_DNR;
    }

    uint64_t minimum_obj_id = INT64_MIN;
    if (kv_cmd->key_low != 0) {
        minimum_obj_id = kv_cmd->key_low + USEROBJECT_OID_LB;
    }

    uint8_t buffer[OSD_LIST_BUFFER_SIZE] = {0x0};
    size_t size = sizeof(buffer);
    ftl_ret_val ftl_ret = FTL_OBJ_LIST(device_index, buffer, &size, minimum_obj_id);
    if (ftl_ret != FTL_SUCCESS) {
        printf("Failed to list objects using FTP API.\n");
        return NVME_FTL_API_FAILED;
    }

    if (size < OSD_LIST_VALUES_OFFSET ||
        ((size - OSD_LIST_VALUES_OFFSET) % OSD_KEY_SIZE > 0)) {
        printf("invalid used value from osd_list (%lu)\n", size);
        return NVME_FTL_API_FAILED;
    }

    size -= OSD_LIST_VALUES_OFFSET;
    uint32_t found_keys = size / OSD_KEY_SIZE;
    size_t required_buffer_size = sizeof(uint32_t) + \
        found_keys * NVMECLI_KEY_PADDED;

    // Now, fill it on local buffer
    uint8_t *list_buf = g_malloc0(required_buffer_size);

    *((uint32_t*)list_buf) = found_keys;
    size_t current_offset = sizeof(uint32_t);

    uint8_t *list = buffer + OSD_LIST_VALUES_OFFSET;
    while (size > 0) {
        uint64_t found_id = get_ntohll(list) - USEROBJECT_OID_LB;
        *(uint16_t *)(&list_buf[current_offset]) = NVMECLI_KEY_SIZE;
        memcpy(&list_buf[current_offset + sizeof(uint16_t)], (uint8_t*)&found_id,
            sizeof(found_id));
        size -= OSD_KEY_SIZE;
        list += OSD_KEY_SIZE;
        current_offset += NVMECLI_KEY_PADDED;
    }

    uint16_t status = nvme_dma_read_prp(n, (void*)list_buf, required_buffer_size, kv_cmd->prp1, kv_cmd->prp2);
    g_free(list_buf);
    if (unlikely(status != NVME_SUCCESS)) {
        printf("Failed write %d\n", (int)status);
        return status;
    }

    req->cqe.result = required_buffer_size;
    return NVME_SUCCESS;
}

static uint16_t nvme_ftl_exist(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeKvCmd *kv_cmd = (NvmeKvCmd *)cmd;
    uint8_t device_index = get_device_index(n);
    if (INVALID_DEVICE_INDEX == device_index)
    {
        printf("Failed to get device index\n");
        return NVME_FTL_API_FAILED;
    }

    if (kv_cmd->key_low > UINT64_MAX - USEROBJECT_OID_LB) {
        printf("Overflow detected while calculating the object id!\n");
        return NVME_INVALID_KEY;
        // TODO: after fixing issue with kv_cmd->key_high, we
        // should reconsider this if condition.
    }

    // TODO: fix issue with kv_cmd->key_high
    obj_id_t object = {
        .object_id = USEROBJECT_OID_LB + kv_cmd->key_low,
        .partition_id = PARTITION_PID_LB
    };

    if (!lookup_object(device_index, object.object_id))
        req->cqe.result = NVME_KEY_DOES_NOT_EXIST;
    else
        req->cqe.result = 0;

    return NVME_SUCCESS;
}

static uint16_t nvme_kv_io_cmd(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_KV_CMD_STORE:
        return nvme_ftl_store(n, ns, cmd, req);
    case NVME_KV_CMD_RETREIVE:
        return nvme_ftl_retreive(n, ns, cmd, req);
    case NVME_KV_CMD_DELETE:
        return nvme_ftl_delete(n, ns, cmd, req);
    case NVME_KV_CMD_LIST:
        return nvme_ftl_list(n, ns, cmd, req);
    case NVME_KV_CMD_EXIST:
    	return nvme_ftl_exist(n, ns, cmd, req);
    default:
        printf("@@@@ Got cmd %d\n", cmd->opcode);
        trace_nvme_err_invalid_opc(cmd->opcode);
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
        trace_nvme_err_invalid_ns(nsid, n->num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    return n->feature.key_value_csi ?
        nvme_kv_io_cmd(n, ns, cmd, req) :
        nvme_nvm_io_cmd(n, ns, cmd, req);
}

static void nvme_free_sq(NvmeSQueue *sq, NvmeCtrl *n)
{
    n->sq[sq->sqid] = NULL;
    timer_del(sq->timer);
    timer_free(sq->timer);
    g_free(sq->io_req);
    if (sq->sqid) {
        g_free(sq);
    }
}

static uint16_t nvme_del_sq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeRequest *req, *next;
    NvmeSQueue *sq;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (unlikely(!qid || !nvme_used_sqid(n, qid))) {
        trace_nvme_err_invalid_del_sq(qid);
        return NVME_INVALID_QID | NVME_DNR;
    }

    trace_nvme_del_sq(qid);

    sq = n->sq[qid];
    while (!QTAILQ_EMPTY(&sq->out_req_list)) {
        req = QTAILQ_FIRST(&sq->out_req_list);
        assert(req->aiocb);
        blk_aio_cancel(req->aiocb);
    }
    if (nvme_used_cqid(n, sq->cqid)) {
        cq = n->cq[sq->cqid];
        QTAILQ_REMOVE(&cq->sq_list, sq, entry);

        nvme_post_cqes(cq);
        QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
            if (req->sq == sq) {
                QTAILQ_REMOVE(&cq->req_list, req, entry);
                QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
            }
        }
    }

    nvme_free_sq(sq, n);
    return NVME_SUCCESS;
}

static void nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t sqid, uint16_t cqid, uint16_t size)
{
    int i;
    NvmeCQueue *cq;

    sq->ctrl = n;
    sq->dma_addr = dma_addr;
    sq->sqid = sqid;
    sq->size = size;
    sq->cqid = cqid;
    sq->head = sq->tail = 0;
    sq->io_req = g_new(NvmeRequest, sq->size);
    QTAILQ_INIT(&sq->req_list);
    QTAILQ_INIT(&sq->out_req_list);
    for (i = 0; i < sq->size; i++) {
        sq->io_req[i].sq = sq;
        QTAILQ_INSERT_TAIL(&(sq->req_list), &sq->io_req[i], entry);
    }
    sq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_process_sq, sq);

    assert(n->cq[cqid]);
    cq = n->cq[cqid];
    QTAILQ_INSERT_TAIL(&(cq->sq_list), sq, entry);
    n->sq[sqid] = sq;
}

static uint16_t nvme_create_sq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeSQueue *sq;
    NvmeCreateSq *c = (NvmeCreateSq *)cmd;

    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t sqid = le16_to_cpu(c->sqid);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->sq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    trace_nvme_create_sq(prp1, sqid, cqid, qsize, qflags);

    if (unlikely(!cqid || !nvme_used_cqid(n, cqid))) {
        trace_nvme_err_invalid_create_sq_cqid(cqid);
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (unlikely(!sqid || !nvme_valid_sqid(n, sqid) || nvme_used_sqid(n, sqid))) {
        trace_nvme_err_invalid_create_sq_sqid(sqid);
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(n->bar.cap))) {
        trace_nvme_err_invalid_create_sq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(!prp1 || prp1 & (n->page_size - 1))) {
        trace_nvme_err_invalid_create_sq_addr(prp1);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (unlikely(!(NVME_SQ_FLAGS_PC(qflags)))) {
        trace_nvme_err_invalid_create_sq_qflags(NVME_SQ_FLAGS_PC(qflags));
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    sq = g_malloc0(sizeof(*sq));
    nvme_init_sq(sq, n, prp1, sqid, cqid, qsize + 1);
    return NVME_SUCCESS;
}

static void nvme_free_cq(NvmeCQueue *cq, NvmeCtrl *n)
{
    n->cq[cq->cqid] = NULL;
    timer_del(cq->timer);
    timer_free(cq->timer);
    timer_del(cq->async_req_timer);
    timer_free(cq->async_req_timer);
    msix_vector_unuse(&n->parent_obj, cq->vector);
    if (cq->cqid) {
        g_free(cq);
    }
}

static uint16_t nvme_del_cq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (unlikely(!qid || !nvme_used_cqid(n, qid))) {
        trace_nvme_err_invalid_del_cq_cqid(qid);
        return NVME_INVALID_QID | NVME_DNR;
    }

    cq = n->cq[qid];
    if (unlikely(!QTAILQ_EMPTY(&cq->sq_list))) {
        trace_nvme_err_invalid_del_cq_notempty(qid);
        return NVME_INVALID_QUEUE_DEL;
    }
    trace_nvme_del_cq(qid);
    nvme_free_cq(cq, n);
    return NVME_SUCCESS;
}

static void nvme_init_cq(NvmeCQueue *cq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t cqid, uint16_t vector, uint16_t size, uint16_t irq_enabled)
{
    cq->ctrl = n;
    cq->cqid = cqid;
    cq->size = size;
    cq->dma_addr = dma_addr;
    cq->phase = 1;
    cq->irq_enabled = irq_enabled;
    cq->vector = vector;
    cq->head = cq->tail = 0;
    cq->outstanding_asyncs = 0;
    QTAILQ_INIT(&cq->req_list);
    QTAILQ_INIT(&cq->async_req_list);
    QTAILQ_INIT(&cq->event_queue);
    QTAILQ_INIT(&cq->sq_list);
    msix_vector_use(&n->parent_obj, cq->vector);
    n->cq[cqid] = cq;
    cq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_post_cqes, cq);
    cq->async_req_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_async_req, cq);
}

static uint16_t nvme_create_cq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeCQueue *cq;
    NvmeCreateCq *c = (NvmeCreateCq *)cmd;
    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t vector = le16_to_cpu(c->irq_vector);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->cq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    trace_nvme_create_cq(prp1, cqid, vector, qsize, qflags,
                         NVME_CQ_FLAGS_IEN(qflags) != 0);

    if (unlikely(!cqid || !nvme_valid_cqid(n, cqid) || nvme_used_cqid(n, cqid))) {
        trace_nvme_err_invalid_create_cq_cqid(cqid);
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(n->bar.cap))) {
        trace_nvme_err_invalid_create_cq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(!prp1)) {
        trace_nvme_err_invalid_create_cq_addr(prp1);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (unlikely(vector >= n->num_queues)) {
        trace_nvme_err_invalid_create_cq_vector(vector);
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (unlikely(!(NVME_CQ_FLAGS_PC(qflags)))) {
        trace_nvme_err_invalid_create_cq_qflags(NVME_CQ_FLAGS_PC(qflags));
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    cq = g_malloc0(sizeof(*cq));
    nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
        NVME_CQ_FLAGS_IEN(qflags));
    return NVME_SUCCESS;
}

static uint16_t nvme_identify_ctrl(NvmeCtrl *n, NvmeIdentify *c)
{
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);

    trace_nvme_identify_ctrl();

    return nvme_dma_read_prp(n, (uint8_t *)&n->id_ctrl, sizeof(n->id_ctrl),
        prp1, prp2);
}

static uint16_t nvme_identify_ns(NvmeCtrl *n, NvmeIdentify *c)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);

    trace_nvme_identify_ns(nsid);

    if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
        trace_nvme_err_invalid_ns(nsid, n->num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    return nvme_dma_read_prp(n, (uint8_t *)&ns->id_ns, sizeof(ns->id_ns),
        prp1, prp2);
}

static uint16_t nvme_identify_nslist(NvmeCtrl *n, NvmeIdentify *c)
{
    static const int data_len = 4096;
    uint32_t min_nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);
    uint32_t *list;
    uint16_t ret;
    int i, j = 0;

    trace_nvme_identify_nslist(min_nsid);

    list = g_malloc0(data_len);
    for (i = 0; i < n->num_namespaces; i++) {
        if (i < min_nsid) {
            continue;
        }
        list[j++] = cpu_to_le32(i + 1);
        if (j == data_len / sizeof(uint32_t)) {
            break;
        }
    }
    ret = nvme_dma_read_prp(n, (uint8_t *)list, data_len, prp1, prp2);
    g_free(list);
    return ret;
}


static uint16_t nvme_identify(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;

    switch (le32_to_cpu(c->cns)) {
    case 0x00:
        return nvme_identify_ns(n, c);
    case 0x01:
        return nvme_identify_ctrl(n, c);
    case 0x02:
        return nvme_identify_nslist(n, c);
    default:
        trace_nvme_err_invalid_identify_cns(le32_to_cpu(c->cns));
        return NVME_INVALID_FIELD | NVME_DNR;
    }
}

static uint16_t nvme_get_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint8_t fid = (uint8_t)le32_to_cpu(cmd->cdw10); /* fid uses only 8 bits */
    uint32_t result;

    switch (fid) {
    case NVME_VOLATILE_WRITE_CACHE:
        result = blk_enable_write_cache(n->conf.blk);
        trace_nvme_getfeat_vwcache(result ? "enabled" : "disabled");
        break;
    case NVME_NUMBER_OF_QUEUES:
        result = cpu_to_le32((n->num_queues - 2) | ((n->num_queues - 2) << 16));
        trace_nvme_getfeat_numq(result);
        break;
    case NVME_ARBITRATION:
        result = n->feature.arbitration;
        break;
    case NVME_POWER_MANAGEMENT:
        result = n->feature.power_mgmt;
        break;
    case NVME_LBA_RANGE_TYPE:
        return NVME_DNR; /* TODO: add support to lba range type */
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        result = n->feature.temp_thresh;
        break;
    case NVME_ERROR_RECOVERY:
        result = n->feature.err_rec;
        break;
    case NVME_INTERRUPT_COALESCING:
        result = n->feature.int_coalescing;
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        result = n->feature.int_vector_config;
        break;
    case NVME_WRITE_ATOMICITY:
        result = n->feature.write_atomicity;
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        result = n->feature.async_config;
        break;
    case NVME_SOFTWARE_PROGRESS_MARKER:
        result = n->feature.sw_prog_marker;
        break;
    case NVME_SET_KEY_VALUE_CSI:
        result = n->feature.key_value_csi;
        break;
    default:
        trace_nvme_err_invalid_getfeat(fid);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    req->cqe.result = result;
    return NVME_SUCCESS;
}

static uint16_t nvme_set_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint8_t fid = (uint8_t)le32_to_cpu(cmd->cdw10); /* fid uses only 8 bits */
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);

    switch (fid) {
    case NVME_VOLATILE_WRITE_CACHE:
        blk_set_enable_write_cache(n->conf.blk, dw11 & 1);
        break;
    case NVME_NUMBER_OF_QUEUES:
        trace_nvme_setfeat_numq((dw11 & 0xFFFF) + 1,
                                ((dw11 >> 16) & 0xFFFF) + 1,
                                n->num_queues - 1, n->num_queues - 1);
        req->cqe.result =
            cpu_to_le32((n->num_queues - 2) | ((n->num_queues - 2) << 16));
        break;
    case NVME_ARBITRATION:
        n->feature.arbitration = dw11;
        break;
    case NVME_POWER_MANAGEMENT:
        n->feature.power_mgmt = dw11;
        break;
    case NVME_LBA_RANGE_TYPE:
        return NVME_DNR; /* TODO: add support to lba range type */
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        n->feature.temp_thresh = dw11;
        if (n->feature.temp_thresh <= NVME_TEMPERATURE &&
                !n->temp_warn_issued) {
            n->temp_warn_issued = 1;
            enqueue_async_event(n, event_type_smart,
                event_info_smart_temp_thresh, NVME_LOG_SMART_INFORMATION);
        }
        break;
    case NVME_ERROR_RECOVERY:
        n->feature.err_rec = dw11;
        break;
    case NVME_INTERRUPT_COALESCING:
        n->feature.int_coalescing = dw11;
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        n->feature.int_vector_config = dw11;
        break;
    case NVME_WRITE_ATOMICITY:
        n->feature.write_atomicity = dw11;
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        n->feature.async_config = dw11;
        break;
    case NVME_SOFTWARE_PROGRESS_MARKER:
        n->feature.sw_prog_marker = dw11;
        break;
    case NVME_SET_KEY_VALUE_CSI:
        n->feature.key_value_csi = dw11;
        break;
    default:
        trace_nvme_err_invalid_setfeat(fid);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

/**
 * builds an empty log page
 *
 * TODO: build a real log page
 */
static uint16_t adm_cmd_smart_info(NvmeCtrl *n, NvmeCmd *cmd,  NvmeRequest *req)
{
    uint32_t len, buf_len, trans_len;
    NvmeSmartLog smart_log;

    buf_len = (((cmd->cdw10 >> 16) & 0xfff) + 1) * 4;
    trans_len = sizeof(smart_log) < buf_len ? sizeof(smart_log) : buf_len;

    memset(&smart_log, 0x0, sizeof(smart_log));
    if (cmd->nsid == 0xffffffff || !(n->id_ctrl.lpa & 0x1)) {
        /* TODO: return info for entire device */
    } else if (cmd->nsid > 0 && cmd->nsid <= n->num_namespaces &&
        (n->id_ctrl.lpa & 0x1)) {
        /* TODO: return info for specific ns */
    } else {
        return NVME_INVALID_NSID;
    }

    /* just make up a temperature. 0x143 Kelvin is 50 degrees C. */
    smart_log.temperature[0] = NVME_TEMPERATURE & 0xff;
    smart_log.temperature[1] = (NVME_TEMPERATURE >> 8) & 0xff;

    smart_log.available_spare_threshold = NVME_SPARE_THRESH;
    if (smart_log.available_spare <= NVME_SPARE_THRESH) {
        smart_log.critical_warning |= 1 << 0;
    }

    len = (PAGE_SIZE - (cmd->prp1 % PAGE_SIZE)) < trans_len ? (PAGE_SIZE - (cmd->prp1 % PAGE_SIZE)) : trans_len;
    cpu_physical_memory_rw(cmd->prp1, (uint8_t *)&smart_log, len, 1);
    if (len < trans_len) {
        cpu_physical_memory_rw(cmd->prp2, (uint8_t *)((uint8_t *)&smart_log + len),
            trans_len - len, 1);
    }

    return NVME_SUCCESS;
}

/**
 * builds an (almost) empty log info page
 *
 * TODO: build a real log page
 */
static uint16_t adm_cmd_fw_log_info(NvmeCtrl *n, NvmeCmd *cmd,  NvmeRequest *req)
{
    NvmeFwSlotInfoLog fw_info;
    uint32_t len, buf_len, trans_len;

    buf_len = (((cmd->cdw10 >> 16) & 0xfff) + 1) * 4;
    trans_len = sizeof(fw_info) < buf_len ? sizeof(fw_info) : buf_len;

    memset(&fw_info, 0x0, sizeof(fw_info));

    // TODO: find a way to fetch the page_size from vssim.c
    len = (PAGE_SIZE - (cmd->prp1 % PAGE_SIZE)) < trans_len ? (PAGE_SIZE - (cmd->prp1 % PAGE_SIZE)) : trans_len;
    cpu_physical_memory_rw(cmd->prp1, (uint8_t *)&fw_info, len, 1);
    if (len < trans_len) {
        cpu_physical_memory_rw(cmd->prp2, (uint8_t *)((uint8_t *)&fw_info + len),
            trans_len - len, 1);
    }

    return NVME_SUCCESS;
}

/**
 * This is a dummy function
 *
 * TODO: Implement the functions adm_cmd_smart_info, adm_cmd_fw_log_info
 */
static uint16_t nvme_get_log_page(NvmeCtrl *n, NvmeCmd *cmd,  NvmeRequest *req)
{
    uint8_t lid = (uint8_t)le32_to_cpu(cmd->cdw10); /* lid uses only 8 bits */

    switch (lid) {
    case NVME_LOG_ERROR_INFO:
        return NVME_SUCCESS;
        break;
    case NVME_LOG_SMART_INFO:
        return adm_cmd_smart_info(n, cmd,  req);
        break;
    case NVME_LOG_FW_SLOT_INFO:
        return adm_cmd_fw_log_info(n, cmd, req);
        break;
    default:
        return NVME_CMD_ABORT_FAILED_FUSE | NVME_INVALID_CQID;
        break;
    }
}

static uint16_t adm_cmd_async_ev_req(NvmeCtrl *n, NvmeCmd *cmd,  NvmeRequest *req)
{
    NvmeCQueue *cq = n->cq[req->sq->cqid]; /* since this is an admin request, this is the same as n->admin_cq */
    if (cq->outstanding_asyncs > n->id_ctrl.aerl){
        req->cqe.cid = n->id_ctrl.aerl;
        req->cqe.rsvd = cq->outstanding_asyncs;
        return NVME_AER_LIMIT_EXCEEDED;
    }

    cq->outstanding_asyncs++;
    req->status = NVME_SUCCESS;
    QTAILQ_REMOVE(&req->sq->out_req_list, req, entry);
    QTAILQ_INSERT_TAIL(&cq->async_req_list, req, entry);
    timer_mod(cq->async_req_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 10000);

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_DELETE_SQ:
        return nvme_del_sq(n, cmd);
    case NVME_ADM_CMD_CREATE_SQ:
        return nvme_create_sq(n, cmd);
    case NVME_ADM_CMD_DELETE_CQ:
        return nvme_del_cq(n, cmd);
    case NVME_ADM_CMD_CREATE_CQ:
        return nvme_create_cq(n, cmd);
    case NVME_ADM_CMD_IDENTIFY:
        return nvme_identify(n, cmd);
    case NVME_ADM_CMD_SET_FEATURES:
        return nvme_set_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_FEATURES:
        return nvme_get_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_LOG_PAGE:
        return nvme_get_log_page(n, cmd, req);
    case NVME_ADM_CMD_ASYNC_EV_REQ:
        return adm_cmd_async_ev_req(n, cmd, req);
    default:
        trace_nvme_err_invalid_admin_opc(cmd->opcode);
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_process_sq(void *opaque)
{
    NvmeSQueue *sq = opaque;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeRequest *req;
    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
        addr = sq->dma_addr + sq->head * n->sqe_size;
        nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
        nvme_inc_sq_head(sq);

        req = QTAILQ_FIRST(&sq->req_list);
        QTAILQ_REMOVE(&sq->req_list, req, entry);
        QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);
        memset(&req->cqe, 0, sizeof(req->cqe));
        req->cqe.cid = cmd.cid;

        status = sq->sqid ? nvme_io_cmd(n, &cmd, req) :
            nvme_admin_cmd(n, &cmd, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req);
        }
    }
}

static void nvme_clear_ctrl(NvmeCtrl *n, bool reset)
{
    int i;

    for (i = 0; i < n->num_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i < n->num_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }

    if (reset) {
        // Reset clears all except for AWA, ASW, ACQ
        n->bar.cc = 0;
        n->bar.csts = 0;
    }

    // Update the IRQ status
    n->bar.intmc = n->bar.intms = 0;
    n->irq_status = 0;
    nvme_irq_check(n);

    blk_flush(n->conf.blk);
}

static int nvme_start_ctrl(NvmeCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (unlikely(n->cq[0])) {
        trace_nvme_err_startfail_cq();
        return -1;
    }
    if (unlikely(n->sq[0])) {
        trace_nvme_err_startfail_sq();
        return -1;
    }
    if (unlikely(!n->bar.asq)) {
        trace_nvme_err_startfail_nbarasq();
        return -1;
    }
    if (unlikely(!n->bar.acq)) {
        trace_nvme_err_startfail_nbaracq();
        return -1;
    }
    if (unlikely(n->bar.asq & (page_size - 1))) {
        trace_nvme_err_startfail_asq_misaligned(n->bar.asq);
        return -1;
    }
    if (unlikely(n->bar.acq & (page_size - 1))) {
        trace_nvme_err_startfail_acq_misaligned(n->bar.acq);
        return -1;
    }
    if (unlikely(NVME_CC_MPS(n->bar.cc) <
                 NVME_CAP_MPSMIN(n->bar.cap))) {
        trace_nvme_err_startfail_page_too_small(
                    NVME_CC_MPS(n->bar.cc),
                    NVME_CAP_MPSMIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_MPS(n->bar.cc) >
                 NVME_CAP_MPSMAX(n->bar.cap))) {
        trace_nvme_err_startfail_page_too_large(
                    NVME_CC_MPS(n->bar.cc),
                    NVME_CAP_MPSMAX(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOCQES(n->bar.cc) <
                 NVME_CTRL_CQES_MIN(n->id_ctrl.cqes))) {
        trace_nvme_err_startfail_cqent_too_small(
                    NVME_CC_IOCQES(n->bar.cc),
                    NVME_CTRL_CQES_MIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOCQES(n->bar.cc) >
                 NVME_CTRL_CQES_MAX(n->id_ctrl.cqes))) {
        trace_nvme_err_startfail_cqent_too_large(
                    NVME_CC_IOCQES(n->bar.cc),
                    NVME_CTRL_CQES_MAX(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOSQES(n->bar.cc) <
                 NVME_CTRL_SQES_MIN(n->id_ctrl.sqes))) {
        trace_nvme_err_startfail_sqent_too_small(
                    NVME_CC_IOSQES(n->bar.cc),
                    NVME_CTRL_SQES_MIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOSQES(n->bar.cc) >
                 NVME_CTRL_SQES_MAX(n->id_ctrl.sqes))) {
        trace_nvme_err_startfail_sqent_too_large(
                    NVME_CC_IOSQES(n->bar.cc),
                    NVME_CTRL_SQES_MAX(n->bar.cap));
        return -1;
    }
    if (unlikely(!NVME_AQA_ASQS(n->bar.aqa))) {
        trace_nvme_err_startfail_asqent_sz_zero();
        return -1;
    }
    if (unlikely(!NVME_AQA_ACQS(n->bar.aqa))) {
        trace_nvme_err_startfail_acqent_sz_zero();
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = page_size;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);
    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
        NVME_AQA_ACQS(n->bar.aqa) + 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
        NVME_AQA_ASQS(n->bar.aqa) + 1);

    return 0;
}

static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data,
    unsigned size)
{
    if (unlikely(offset & (sizeof(uint32_t) - 1))) {
        NVME_GUEST_ERR(nvme_ub_mmiowr_misaligned32,
                       "MMIO write not 32-bit aligned,"
                       " offset=0x%"PRIx64"", offset);
        /* should be ignored, fall through for now */
    }

    if (unlikely(size < sizeof(uint32_t))) {
        NVME_GUEST_ERR(nvme_ub_mmiowr_toosmall,
                       "MMIO write smaller than 32-bits,"
                       " offset=0x%"PRIx64", size=%u",
                       offset, size);
        /* should be ignored, fall through for now */
    }

    switch (offset) {
    case 0xc:   /* INTMS */
        if (unlikely(msix_enabled(&(n->parent_obj)))) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_intmask_with_msix,
                           "undefined access to interrupt mask set"
                           " when MSI-X is enabled");
            /* should be ignored, fall through for now */
        }
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        trace_nvme_mmio_intm_set(data & 0xffffffff,
                                 n->bar.intmc);
        nvme_irq_check(n);
        break;
    case 0x10:  /* INTMC */
        if (unlikely(msix_enabled(&(n->parent_obj)))) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_intmask_with_msix,
                           "undefined access to interrupt mask clr"
                           " when MSI-X is enabled");
            /* should be ignored, fall through for now */
        }
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        trace_nvme_mmio_intm_clr(data & 0xffffffff,
                                 n->bar.intmc);
        nvme_irq_check(n);
        break;
    case 0x14:  /* CC */
        trace_nvme_mmio_cfg(data & NVME_CC_WR_MASK);

        uint32_t previous_cc = n->bar.cc;

        // CC is all writeable
        n->bar.cc = data & NVME_CC_WR_MASK;

        if (NVME_CC_EN(data) && !NVME_CC_EN(previous_cc)) {
            if (unlikely(nvme_start_ctrl(n))) {
                trace_nvme_err_startfail();
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                trace_nvme_mmio_start_success();
                n->bar.csts = NVME_CSTS_READY;
            }

        } else if (!NVME_CC_EN(data) && NVME_CC_EN(previous_cc)) {
            trace_nvme_mmio_stopped();
            nvme_clear_ctrl(n, true);

        }

        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(previous_cc))) {
            trace_nvme_mmio_shutdown_set();
            nvme_clear_ctrl(n, false);
            n->bar.csts |= NVME_CSTS_SHST_COMPLETE;

        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(previous_cc)) {
            trace_nvme_mmio_shutdown_cleared();
            n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;

        }

        break;
    case 0x1C:  /* CSTS */
        if (data & (1 << 4)) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_ssreset_w1c_unsupported,
                           "attempted to W1C CSTS.NSSRO"
                           " but CAP.NSSRS is zero (not supported)");
        } else if (data != 0) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_ro_csts,
                           "attempted to set a read only bit"
                           " of controller status");
        }
        break;
    case 0x20:  /* NSSR */
        if (data == 0x4E564D65) {
            trace_nvme_ub_mmiowr_ssreset_unsupported();
        } else {
            /* The spec says that writes of other values have no effect */
            return;
        }
        break;
    case 0x24:  /* AQA */
        n->bar.aqa = data & NVME_AQA_WR_MASK;
        trace_nvme_mmio_aqattr(n->bar.aqa);
        break;
    case 0x28:  /* ASQ */
        n->bar.asq = data & NVME_ASQ_WR_MASK;
        trace_nvme_mmio_asqaddr(n->bar.asq);
        break;
    case 0x2c:  /* ASQ hi */
        n->bar.asq |= (data << 32) & NVME_ASQ_WR_MASK;
        trace_nvme_mmio_asqaddr_hi(data, n->bar.asq);
        break;
    case 0x30:  /* ACQ */
        n->bar.acq = data & NVME_ACQ_WR_MASK;
        trace_nvme_mmio_acqaddr(n->bar.acq);
        break;
    case 0x34:  /* ACQ hi */
        n->bar.acq |= (data << 32) & NVME_ACQ_WR_MASK;
        trace_nvme_mmio_acqaddr_hi(data, n->bar.acq);
        break;
    case 0x38:  /* CMBLOC */
        NVME_GUEST_ERR(nvme_ub_mmiowr_cmbloc_reserved,
                       "invalid write to reserved CMBLOC"
                       " when CMBSZ is zero, ignored");
        return;
    case 0x3C:  /* CMBSZ */
        NVME_GUEST_ERR(nvme_ub_mmiowr_cmbsz_readonly,
                       "invalid write to read only CMBSZ, ignored");
        return;
    default:
        NVME_GUEST_ERR(nvme_ub_mmiowr_invalid,
                       "invalid MMIO write,"
                       " offset=0x%"PRIx64", data=%"PRIx64"",
                       offset, data);
        break;
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;

    if (unlikely(addr & (sizeof(uint32_t) - 1))) {
        NVME_GUEST_ERR(nvme_ub_mmiord_misaligned32,
                       "MMIO read not 32-bit aligned,"
                       " offset=0x%"PRIx64"", addr);
        /* should RAZ, fall through for now */
    } else if (unlikely(size < sizeof(uint32_t))) {
        NVME_GUEST_ERR(nvme_ub_mmiord_toosmall,
                       "MMIO read smaller than 32-bits,"
                       " offset=0x%"PRIx64"", addr);
        /* should RAZ, fall through for now */
    }

    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    } else {
        NVME_GUEST_ERR(nvme_ub_mmiord_invalid_ofs,
                       "MMIO read beyond last register,"
                       " offset=0x%"PRIx64", returning 0", addr);
    }

    return val;
}

static void nvme_process_db(NvmeCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;

    if (unlikely(addr & ((1 << 2) - 1))) {
        NVME_GUEST_ERR(nvme_ub_db_wr_misaligned,
                       "doorbell write not 32-bit aligned,"
                       " offset=0x%"PRIx64", ignoring", addr);
        return;
    }

    if (((addr - 0x1000) >> 2) & 1) {
        /* Completion queue doorbell write */

        uint16_t new_head = val & 0xffff;
        int start_sqs;
        NvmeCQueue *cq;

        qid = (addr - (0x1000 + (1 << 2))) >> 3;
        if (unlikely(!nvme_used_cqid(n, qid))) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_cq,
                           "completion queue doorbell write"
                           " for nonexistent queue,"
                           " sqid=%"PRIu32", ignoring", qid);
            enqueue_async_event(n, event_type_error,
                event_info_err_invalid_sq, NVME_LOG_ERROR_INFORMATION);
            return;
        }

        cq = n->cq[qid];
        if (unlikely(new_head >= cq->size)) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_cqhead,
                           "completion queue doorbell write value"
                           " beyond queue size, sqid=%"PRIu32","
                           " new_head=%"PRIu16", ignoring",
                           qid, new_head);
            enqueue_async_event(n, event_type_error,
                event_info_err_invalid_db, NVME_LOG_ERROR_INFORMATION);
            return;
        }

        /*
         CLARIFICATION
         When CQ was full *before* the db write, nvme_post_cqes skipped processing of responses and
         as a side effect SQ was unable to process new requests (As they are limited by size).
         When CQ is cleared, spawn both processing of all CQs and SQs. As call to timer_mod
         is serial, first handle the CQ to clear any pending requests and then clear the associated SQs.
         */
        start_sqs = nvme_cq_full(cq) ? 1 : 0;
        cq->head = new_head;
        if (start_sqs) {
            NvmeSQueue *sq;
            timer_mod(cq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
            QTAILQ_FOREACH(sq, &cq->sq_list, entry) {
                timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
            }
        }

        // When we have more messages, we should make sure irq is asserted. When MSIx is used
        // this will make sure another notification is sent to the guest.
        if (cq->tail == cq->head) {
            nvme_irq_deassert(n, cq);
        } else {
            nvme_irq_assert(n, cq);
        }
    } else {
        /* Submission queue doorbell write */

        uint16_t new_tail = val & 0xffff;
        NvmeSQueue *sq;

        qid = (addr - 0x1000) >> 3;
        if (unlikely(!nvme_used_sqid(n, qid))) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_sq,
                           "submission queue doorbell write"
                           " for nonexistent queue,"
                           " sqid=%"PRIu32", ignoring", qid);
            enqueue_async_event(n, event_type_error,
                event_info_err_invalid_sq, NVME_LOG_ERROR_INFORMATION);
            return;
        }

        sq = n->sq[qid];
        if (unlikely(new_tail >= sq->size)) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_sqtail,
                           "submission queue doorbell write value"
                           " beyond queue size, sqid=%"PRIu32","
                           " new_tail=%"PRIu16", ignoring",
                           qid, new_tail);
            enqueue_async_event(n, event_type_error,
                event_info_err_invalid_db, NVME_LOG_ERROR_INFORMATION);
            return;
        }

        sq->tail = new_tail;
        timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    }
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    } else if (addr >= 0x1000) {
        nvme_process_db(n, addr, data);
    }
}

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    memcpy(&n->cmbuf[addr], &data, size);
}

static uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size)
{
    uint64_t val;
    NvmeCtrl *n = (NvmeCtrl *)opaque;

    memcpy(&val, &n->cmbuf[addr], size);
    return val;
}

static const MemoryRegionOps nvme_cmb_ops = {
    .read = nvme_cmb_read,
    .write = nvme_cmb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static uint32_t nvme_pci_read_config(PCIDevice *pci_dev, uint32_t addr, int len)
{
    uint32_t val; /* Value to be returned */

    val = pci_default_read_config(pci_dev, addr, len);
    if (ranges_overlap(addr, len, PCI_BASE_ADDRESS_2, 4) && (!(pci_dev->config[PCI_COMMAND] & PCI_COMMAND_IO))) {
        /* When CMD.IOSE is not set */
        val = 0 ;
    }

    return val;
}

static void nvme_realize(PCIDevice *pci_dev, Error **errp)
{
    static const uint16_t nvme_pm_offset = 0x80;
    static const uint16_t nvme_pcie_offset = nvme_pm_offset + PCI_PM_SIZEOF;

    NvmeCtrl *n = NVME(pci_dev);
    NvmeIdCtrl *id = &n->id_ctrl;

    int i;
    int64_t bs_size;
    uint8_t *pci_conf;
    uint8_t *pci_wmask;

    if (!n->conf.blk) {
        error_setg(errp, "drive property not set");
        return;
    }

    bs_size = blk_getlength(n->conf.blk);
    if (bs_size < 0) {
        error_setg(errp, "could not get backing file size");
        return;
    }

    blkconf_serial(&n->conf, &n->serial);
    if (!n->serial) {
        error_setg(errp, "serial property not set");
        return;
    }
    blkconf_blocksizes(&n->conf);
    if (!blkconf_apply_backend_options(&n->conf, blk_is_read_only(n->conf.blk),
                                       false, errp)) {
        return;
    }

    pci_conf = pci_dev->config;
    pci_wmask = pci_dev->wmask;
    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_dev->config, 0x2);
    pci_config_set_class(pci_dev->config, PCI_CLASS_STORAGE_EXPRESS);

    // Configure the PMC capability
    (void)pci_add_capability(pci_dev, PCI_CAP_ID_PM, nvme_pm_offset, PCI_PM_SIZEOF, errp);
    if (NULL != *errp) {
        return;
    }

    //  - PCI Power Management v1.2, No PME support, No Soft Reset, Make state writeable
    pci_set_word(pci_conf + nvme_pm_offset + PCI_PM_PMC, PCI_PM_CAP_VER_1_2);
    pci_set_word(pci_conf + nvme_pm_offset + PCI_PM_CTRL, PCI_PM_CTRL_NO_SOFT_RESET);
    pci_set_word(pci_wmask + nvme_pm_offset + PCI_PM_CTRL, PCI_PM_CTRL_STATE_MASK);

    // Disable QEMU default QEMU_PCIE_LNKSTA_DLLLA to disabled active flag in the Link Status Register of PCIE
    pci_dev->cap_present &= ~(QEMU_PCIE_LNKSTA_DLLLA);

    // PCIE Capability
    pcie_endpoint_cap_init(&n->parent_obj, nvme_pcie_offset);

    // PCIE Function Level Reset (FLRC) as required by 1.2 spec
    pcie_cap_flr_init(&n->parent_obj);

    // PCIE Configured with L0s by default by QEMU, configure missing AOC flag required by compliance
    pci_long_test_and_set_mask(pci_conf + pci_dev->exp.exp_cap + PCI_EXP_LNKCAP, PCI_EXP_LNKCAP_AOC);

    // Compliance requires Completion Timeout Disable Supported (CTDS).
    pci_long_test_and_set_mask(pci_conf + pci_dev->exp.exp_cap + PCI_EXP_DEVCAP2, PCI_EXP_DEVCAP2_CTDS);

    // Make the End-End TLP Prefix readonly as NVME spec doesnt acknowledge this field
    pci_word_test_and_clear_mask(pci_wmask + pci_dev->exp.exp_cap + PCI_EXP_DEVCTL2, PCI_EXP_DEVCTL2_EETLPPB);

    n->num_namespaces = 1;
    n->num_queues = 64;
    n->reg_size = pow2ceil(0x2000 + 2 * (n->num_queues + 1) * 4);
    n->ns_size = bs_size / (uint64_t)n->num_namespaces;

    n->namespaces = g_new0(NvmeNamespace, n->num_namespaces);
    n->sq = g_new0(NvmeSQueue *, n->num_queues);
    n->cq = g_new0(NvmeCQueue *, n->num_queues);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n,
                          "nvme", n->reg_size);
    pci_register_bar(&n->parent_obj, 0,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
        &n->iomem);

    // Expose the NVME memory through Address Space IO (Optional by spec)
    pci_register_bar(&n->parent_obj, 2, PCI_BASE_ADDRESS_SPACE_IO, &n->iomem);

    msix_init_exclusive_bar(&n->parent_obj, n->num_queues, 4, NULL);

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));
    strpadcpy((char *)id->mn, sizeof(id->mn), "QEMU NVMe Ctrl", ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');
    strpadcpy((char *)id->sn, sizeof(id->sn), n->serial, ' ');
    id->rab = 6;
    id->ieee[0] = 0x00;
    id->ieee[1] = 0x02;
    id->ieee[2] = 0xb3;
    id->oacs = cpu_to_le16(0);
    id->frmw = 7 << 1;
    id->lpa = 1 << 0;
    id->sqes = (0x6 << 4) | 0x6;
    id->cqes = (0x4 << 4) | 0x4;
    id->nn = cpu_to_le32(n->num_namespaces);
    id->oncs = cpu_to_le16(NVME_ONCS_WRITE_ZEROS);
    id->psd[0].mp = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);
    if (blk_enable_write_cache(n->conf.blk)) {
        id->vwc = 1;
    }

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, 0x7ff);
    NVME_CAP_SET_CQR(n->bar.cap, 1);
    NVME_CAP_SET_AMS(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_CSS(n->bar.cap, 1);
    NVME_CAP_SET_MPSMAX(n->bar.cap, 4);

    n->bar.vs = 0x00010200;
    n->bar.intmc = n->bar.intms = 0;

    if (n->cmb_size_mb) {

        NVME_CMBLOC_SET_BIR(n->bar.cmbloc, 2);
        NVME_CMBLOC_SET_OFST(n->bar.cmbloc, 0);

        NVME_CMBSZ_SET_SQS(n->bar.cmbsz, 1);
        NVME_CMBSZ_SET_CQS(n->bar.cmbsz, 0);
        NVME_CMBSZ_SET_LISTS(n->bar.cmbsz, 0);
        NVME_CMBSZ_SET_RDS(n->bar.cmbsz, 1);
        NVME_CMBSZ_SET_WDS(n->bar.cmbsz, 1);
        NVME_CMBSZ_SET_SZU(n->bar.cmbsz, 2); /* MBs */
        NVME_CMBSZ_SET_SZ(n->bar.cmbsz, n->cmb_size_mb);

        n->cmbloc = n->bar.cmbloc;
        n->cmbsz = n->bar.cmbsz;

        n->cmbuf = g_malloc0(NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
        memory_region_init_io(&n->ctrl_mem, OBJECT(n), &nvme_cmb_ops, n,
                              "nvme-cmb", NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
        pci_register_bar(&n->parent_obj, NVME_CMBLOC_BIR(n->bar.cmbloc),
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64 |
            PCI_BASE_ADDRESS_MEM_PREFETCH, &n->ctrl_mem);

    }

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        NvmeIdNs *id_ns = &ns->id_ns;
        id_ns->nsfeat = 0;
        id_ns->nlbaf = 0;
        id_ns->flbas = 0;
        id_ns->mc = 0;
        id_ns->dpc = 0;
        id_ns->dps = 0;
        id_ns->lbaf[0].ds = BDRV_SECTOR_BITS;
        id_ns->ncap  = id_ns->nuse = id_ns->nsze =
            cpu_to_le64(n->ns_size >>
                id_ns->lbaf[NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas)].ds);
    }
}

static void nvme_exit(PCIDevice *pci_dev)
{
    NvmeCtrl *n = NVME(pci_dev);

    nvme_clear_ctrl(n, true);

    g_free(n->namespaces);
    g_free(n->cq);
    g_free(n->sq);
    if (n->cmbsz) {
        memory_region_unref(&n->ctrl_mem);
    }

    msix_uninit_exclusive_bar(pci_dev);
}

static Property nvme_props[] = {
    DEFINE_BLOCK_PROPERTIES(NvmeCtrl, conf),
    DEFINE_PROP_STRING("serial", NvmeCtrl, serial),
    DEFINE_PROP_UINT32("cmb_size_mb", NvmeCtrl, cmb_size_mb, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription nvme_vmstate = {
    .name = "nvme",
    .unmigratable = 1,
};

static void nvme_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = nvme_realize;
    pc->config_read = nvme_pci_read_config;
    pc->exit = nvme_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0x5845;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    dc->props = nvme_props;
    dc->vmsd = &nvme_vmstate;
}

static void nvme_instance_init(Object *obj)
{
    NvmeCtrl *s = NVME(obj);
    uint8_t device_index = get_device_index(s);

    device_add_bootindex_property(obj, &s->conf.bootindex,
                                  "bootindex", "/namespace@1,0",
                                  DEVICE(obj), &error_abort);

    INIT_OBJ_STRATEGY(device_index);
}

static void nvme_class_finalize(ObjectClass *obj, void *data)
{
    NvmeCtrl *s = NVME(obj);
    uint8_t device_index = get_device_index(s);

    TERM_OBJ_STRATEGY(device_index);
}

static uint8_t get_device_index(NvmeCtrl* ctrl)
{
    BlockBackend *blk = ctrl->conf.blk;
    if (NULL == blk)
    {
        return INVALID_DEVICE_INDEX;
    }

    BlockDriverState *bs = blk_bs(blk);
    if (NULL == bs)
    {
        return INVALID_DEVICE_INDEX;
    }

    BDRVVSSIMState *s = bs->opaque;
    if (NULL == s)
    {
        return INVALID_DEVICE_INDEX;
    }

    return s->device_index;
}

static const TypeInfo nvme_info = {
    .name           = "nvme",
    .parent         = TYPE_PCI_DEVICE,
    .instance_size  = sizeof(NvmeCtrl),
    .class_init     = nvme_class_init,
    .instance_init  = nvme_instance_init,
    .class_finalize = nvme_class_finalize,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void nvme_register_types(void)
{
    type_register_static(&nvme_info);
}

type_init(nvme_register_types)
