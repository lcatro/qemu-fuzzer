
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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


#define KVM_HYPERCALL "vmcall"


static inline long kvm_hypercall0(unsigned int nr) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr));
    return ret;
}

static inline long kvm_hypercall1(unsigned int nr, unsigned long p1) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1));
    return ret;
}

static inline long kvm_hypercall2(unsigned int nr, unsigned long p1,
                  unsigned long p2) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(p2));
    return ret;
}

static inline long kvm_hypercall3(unsigned int nr, unsigned long p1,
                  unsigned long p2, unsigned long p3) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(p2), "d"(p3));
    return ret;
}

static inline long kvm_hypercall4(unsigned int nr, unsigned long p1,
                  unsigned long p2, unsigned long p3,
                  unsigned long p4) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(p2), "d"(p3), "S"(p4));
    return ret;
}

int is_qemu_fuzzer_kvm_envirement(void) {
    unsigned long result = kvm_hypercall0(HYPERCALL_CHECK_FUZZER);

    printf("result = %X \n",result);

    if (HYPERCALL_FLAG_CHECK_FUZZER == HYPERCALL_LOW_32BIT(result))
        return 1;
    
    return 0;
}

int is_qemu_fuzzer_ready_state(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_CHECK_READY));

    if (HYPERCALL_FLAG_SUCCESS == result)
        return 1;
    
    return 0;
}

int push_fuzzing_record(int random_fuzzing_entry,int random_fuzzing_size,int random_fuzzing_r1,int random_fuzzing_r2) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall4(HYPERCALL_PUSH_RECORD,
        random_fuzzing_entry,
        random_fuzzing_size,
        random_fuzzing_r1,
        random_fuzzing_r2));

    if (HYPERCALL_FLAG_SUCCESS == result)
        return 1;
    else if (HYPERCALL_FLAG_FAIL_FUZZER_OUTLINE == result)
        printf("Check fuzzer like outline\n");
    
    return 0;
}

int get_qemu_fuzzer_target_device(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_DEVICE));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_class(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_CLASS));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_vendor(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_VENDOR));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_revision(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_REVISION));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_mmio_resource(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_MMIO_RESOURCE));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_portio_resource(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_PORTIO_RESOURCE));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}


int main(int argc, char *argv[]) {
    if (!is_qemu_fuzzer_kvm_envirement()) {
        printf("QEMU Fuzzer kvm envirement check running fail ! \n");

        return 1;
    }

    printf("QEMU Fuzzer kvm envirement check success\n");

    int data_aligment = 0;

    if (2 == argc) {
        data_aligment = atoi(argv[1]);
    } else {

    }

    int target_device_id = get_qemu_fuzzer_target_device();
    int target_class_id = get_qemu_fuzzer_target_class();
    int target_vendor_id = get_qemu_fuzzer_target_vendor();
    int target_revision_id = get_qemu_fuzzer_target_revision();
    int target_mmio_resource_id = get_qemu_fuzzer_target_mmio_resource();

    if (-1 == target_device_id ||
        -1 == target_class_id ||
        -1 == target_vendor_id ||
        -1 == target_revision_id ||
        -1 == target_mmio_resource_id) {
        printf("QEMU Fuzzer Get Device Information fail ! \n");

        return 1;
    }

    char* device_name = get_device_name_by_id(target_device_id,target_class_id,target_vendor_id,target_revision_id);
    char* target_device_path = search_target_device(target_device_id,target_class_id,target_vendor_id,target_revision_id);
    int device_register_map_size = 0;
    device_register* device_register_map = get_device_register_map(device_name,&device_register_map_size);
    
    printf("QEMU Fuzzer Target (%s) => DeviceID:%X ClassID:%X VendorID:%X RevisionID:%X \n",
        device_name,target_device_id,target_class_id,target_vendor_id,target_revision_id);
    printf("  => MMIO Resource Id = %d\n",target_mmio_resource_id);

    if (NULL == device_register_map)
        printf("Current Fuzzing Device Lost Register MAP \n");
    else
        printf("Fuzzing Device Map Size == %X \n",device_register_map_size);

    if (NULL == target_device_path) {
        printf("QEMU Fuzzer Search Device fail ! \n");

        return 1;
    }

    char mmio_resource_path[MAX_PATH] = {0};

    sprintf(&mmio_resource_path,"%s/resource%d",target_device_path,target_mmio_resource_id);

    printf("QEMU Fuzzer Search Device Path %s \n",target_device_path);
    printf("  Try to Read MMIO Entry %s \n",mmio_resource_path);
    
    int mmio_handle = open(mmio_resource_path,O_RDWR|O_SYNC);
    struct stat file_state = {0};

    fstat(mmio_handle, &file_state);

    int mmio_mapping_size = file_state.st_size;
    unsigned char* mmio_mapping_memory = mmap(0,mmio_mapping_size,PROT_READ|PROT_WRITE,MAP_SHARED,mmio_handle,0);

    printf("QEMU Fuzzer Mapping Address = %lX(%lX)\n",(unsigned int)mmio_mapping_memory,mmio_mapping_size);

    init_random();

    while (1) {
        while (is_qemu_fuzzer_ready_state()) {  //  fuzzer online
            fuzz_data* random_data = NULL;

            if (NULL == device_register_map)
                random_data = fuzz_random_data_maker(mmio_mapping_size);
            else
                random_data = fuzz_random_data_maker_by_device_register_map(device_register_map,device_register_map_size);

            uint_t fuzz_value = data_maker_number(
                random_data->random_fuzzing_size,
                random_data->random_fuzzing_r1,
                random_data->random_fuzzing_r2
            );

            if (!push_fuzzing_record(
                random_data->random_fuzzing_method,
                random_data->random_fuzzing_size,
                random_data->random_fuzzing_r1,
                random_data->random_fuzzing_r2)) {
                printf("Push Fuzzing Record with VMCALL Error!\n");
                free(random_data);

                continue;
            }

            int fuzz_entry = GET_FUZZ_ENTRY(random_data->random_fuzzing_method);
            int fuzz_io = GET_FUZZ_IO(random_data->random_fuzzing_method);
            int fuzz_offset = GET_FUZZ_OFFSET(random_data->random_fuzzing_method);

            #ifdef STUB_DEBUG_MODE
            printf("Fuzzing Data:%d %d %X %d %X %X\n",
                fuzz_entry,
                fuzz_io,
                fuzz_offset,
                random_data->random_fuzzing_size,
                random_data->random_fuzzing_r1,
                random_data->random_fuzzing_r2);
            usleep(10);
            #endif
            /*
            switch (fuzz_entry) {
                case RANDOM_FUZZING_ENTRY_MMIO:  */
                    if (RANDOM_FUZZING_READ == fuzz_io)
                        mmio_read((memory_address)&mmio_mapping_memory[fuzz_offset],
                                  random_data->random_fuzzing_size);
                    else
                        mmio_write((memory_address)&mmio_mapping_memory[fuzz_offset],
                                   &fuzz_value,
                                   random_data->random_fuzzing_size);
                    /*
                    break;
                case RANDOM_FUZZING_ENTRY_PORTIO:
                    if (RANDOM_FUZZING_READ == fuzz_io) {

                    } else {

                    }
                    
                    break;
                default:
                    break;
            }  */

            free(random_data);
        }

        while (!is_qemu_fuzzer_ready_state()) {  //  fuzzer outline
            printf("QEMU Fuzzer.cc no ready -- Check Fuzzer.cc on hostOS \n");
            sleep(3);
        }
    }


    return 0;
}