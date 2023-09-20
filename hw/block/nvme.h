#ifndef HW_NVME_H
#define HW_NVME_H
#include "qemu/cutils.h"
#include "block/nvme.h"

typedef struct NvmeAsyncEvent {
    QSIMPLEQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

typedef struct NvmeRequest {
    struct NvmeSQueue       *sq;
    BlockAIOCB              *aiocb;
    uint16_t                status;
    bool                    has_sg;
    NvmeCqe                 cqe;
    BlockAcctCookie         acct;
    QEMUSGList              qsg;
    QEMUIOVector            iov;
    QTAILQ_ENTRY(NvmeRequest)entry;
} NvmeRequest;

typedef struct NvmeSQueue {
    struct NvmeCtrl *ctrl;
    uint16_t    sqid;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    size;
    uint64_t    dma_addr;
    QEMUTimer   *timer;
    NvmeRequest *io_req;
    QTAILQ_HEAD(sq_req_list, NvmeRequest) req_list;
    QTAILQ_HEAD(out_req_list, NvmeRequest) out_req_list;
    QTAILQ_ENTRY(NvmeSQueue) entry;
} NvmeSQueue;

typedef struct AsyncResult {
    uint8_t event_type;
    uint8_t event_info;
    uint8_t log_page;
    uint8_t resv;
} AsyncResult;

typedef struct AsyncEvent {
    AsyncResult result;
    QTAILQ_ENTRY(AsyncEvent)entry;
} AsyncEvent;

typedef struct NvmeCQueue {
    struct NvmeCtrl *ctrl;
    uint8_t     phase;
    uint16_t    cqid;
    uint16_t    irq_enabled;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    vector;
    uint32_t    size;
    uint64_t    dma_addr;
    uint8_t    outstanding_asyncs;
    QEMUTimer   *timer;
    QEMUTimer   *async_req_timer;
    QTAILQ_HEAD(sq_list, NvmeSQueue) sq_list;
    QTAILQ_HEAD(cq_req_list, NvmeRequest) req_list;
    QTAILQ_HEAD(async_req_list, NvmeRequest) async_req_list;
    QTAILQ_HEAD(event_queue, AsyncEvent) event_queue;
} NvmeCQueue;

#define NVME_KV_MAX_KEY_LENGTH (16)

typedef struct NvmeKVKey {
    uint16_t len;
    union {
        uint8_t key[NVME_KV_MAX_KEY_LENGTH];
        struct {
            uint64_t key_low;
            uint64_t key_high;
        };
    };
} NvmeKVKey;

typedef struct NvmeFsObj {
    QLIST_ENTRY(NvmeFsObj) node;

	NvmeKVKey key;

	void *value;
	uint32_t value_length;
} NvmeFsObj;

typedef struct NvmeNamespace {
    NvmeIdNs        id_ns;

    // Objects are held in memory for now only for simplicity reasons.
    // They should be stored inside the eVSSIM.
    QLIST_HEAD(, NvmeFsObj) fs_objects;
} NvmeNamespace;

#define TYPE_NVME "nvme"
#define NVME(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_NVME)

typedef struct NvmeCtrl {
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    NvmeBar      bar;
    BlockConf    conf;

    uint32_t    page_size;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint16_t    cqe_size;
    uint16_t    sqe_size;
    uint32_t    reg_size;
    uint32_t    num_namespaces;
    uint32_t    num_queues;
    uint32_t    max_q_ents;
    uint64_t    ns_size;
    uint32_t    cmb_size_mb;
    uint32_t    cmbsz;
    uint32_t    cmbloc;
    uint8_t     *cmbuf;
    uint64_t    irq_status;

    char            *serial;
    NvmeNamespace   *namespaces;
    NvmeSQueue      **sq;
    NvmeCQueue      **cq;
    NvmeSQueue      admin_sq;
    NvmeCQueue      admin_cq;
    NvmeIdCtrl      id_ctrl;

    struct NvmeFeatureVal feature;
    bool temp_warn_issued;
} NvmeCtrl;

#endif /* HW_NVME_H */
