#ifndef VSSIM_H
#define VSSIM_H

#include "stdint.h"

typedef struct BDRVVSSIMState {
    char* memory;
    uint64_t size;
    bool simulator;
    uint8_t device_index;
} BDRVVSSIMState;

#endif /* VSSIM_H */
