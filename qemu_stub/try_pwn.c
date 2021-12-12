
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/dir.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/io.h>

#include "kernel_bridge.h"
#include "fuzzer_device_table.h"
#include "fuzzer_mutite.h"
#include "stub_base.h"


int main(int argc, char *argv[]) {
    if (10 != argc) {
        printf("Argument ERROR !\n");

        return 1;
    }

    int device_id   = atoi(argv[1]);
    int class_id    = atoi(argv[2]);
    int vendor_id   = atoi(argv[3]);
    int revision_id = atoi(argv[4]);
    int resouce_id  = atoi(argv[5]);
    int fuzzing_method = atoi(argv[6]);
    int fuzzing_size   = atoi(argv[7]);
    int fuzzing_r1     = atoi(argv[8]);
    int fuzzing_r2     = atoi(argv[9]);
    int fuzz_entry     = GET_FUZZ_ENTRY(fuzzing_method);
    int fuzz_io        = GET_FUZZ_IO(fuzzing_method);
    int fuzz_offset    = GET_FUZZ_OFFSET(fuzzing_method);

    char* device_path = search_target_device(device_id,class_id,vendor_id,revision_id);

    if (NULL == device_path) {
        printf("Can't Find device \n");

        return 0;
    }

    char temp_path[1024] = {0};

    sprintf(&temp_path,"%s/resource%d",device_path,resouce_id);

    int mmio_handle = open(temp_path,O_RDWR|O_SYNC);
    struct stat file_state = {0};

    fstat(mmio_handle, &file_state);

    int mmio_mapping_size = file_state.st_size;
    unsigned char* mmio_mapping_memory = mmap(0,mmio_mapping_size,PROT_READ|PROT_WRITE,MAP_SHARED,mmio_handle,0);

    uint_t fuzz_value = data_maker_number(
        fuzzing_size,
        fuzzing_r1,
        fuzzing_r2
    );

    printf("Fuzzing Data:%d %d %X %d %X %X\n",
        fuzz_entry,
        fuzz_io,
        fuzz_offset,
        fuzzing_size,
        fuzzing_r1,
        fuzzing_r2);

    switch (fuzz_entry) {
        case RANDOM_FUZZING_ENTRY_MMIO:
            if (RANDOM_FUZZING_READ == fuzz_io)
                mmio_read((memory_address)&mmio_mapping_memory[fuzz_offset],
                          fuzzing_size);
            else
                mmio_write((memory_address)&mmio_mapping_memory[fuzz_offset],
                           &fuzz_value,
                           fuzzing_size);

            break;
        case RANDOM_FUZZING_ENTRY_PORTIO:
            if (RANDOM_FUZZING_READ == fuzz_io) {

            } else {

            }
            
            break;
        default:
            break;
    }

    return 0;
} 