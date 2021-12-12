
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


void mmio_write_by_1byte(memory_address mmio_address,uint8_t data) {
    *((uint8_t*)mmio_address) = data;
}

void mmio_write_by_2byte(memory_address mmio_address,uint16_t data) {
    *((uint16_t*)mmio_address) = data;
}

void mmio_write_by_4byte(memory_address mmio_address,uint32_t data) {
    *((uint32_t*)mmio_address) = data;
}

void mmio_write_by_8byte(memory_address mmio_address,uint64_t data) {
    *((uint64_t*)mmio_address) = data;
}

void mmio_write(memory_address mmio_address,void* data,int data_size) {
    if (1 == data_size) {
        mmio_write_by_1byte(mmio_address,*(uint8_t*)data);
    } else if (2 == data_size) {
        mmio_write_by_2byte(mmio_address,*(uint16_t*)data);
    } else if (4 == data_size) {
        mmio_write_by_4byte(mmio_address,*(uint32_t*)data);
    } else if (8 == data_size) {
        mmio_write_by_8byte(mmio_address,*(uint64_t*)data);
    } else {
        // ......
    }
}

uint8_t mmio_read_by_1byte(memory_address mmio_address) {
    return *((uint8_t*)mmio_address);
}

uint16_t mmio_read_by_2byte(memory_address mmio_address) {
    return *((uint16_t*)mmio_address);
}

uint32_t mmio_read_by_4byte(memory_address mmio_address) {
    return *((uint32_t*)mmio_address);
}

uint64_t mmio_read_by_8byte(memory_address mmio_address) {
    return *((uint64_t*)mmio_address);
}

void mmio_read(memory_address mmio_address,int data_size) {
    if (1 == data_size) {
        *((uint8_t*)mmio_address) = mmio_read_by_1byte(mmio_address);
    } else if (2 == data_size) {
        *((uint16_t*)mmio_address) = mmio_read_by_2byte(mmio_address);
    } else if (4 == data_size) {
        *((uint32_t*)mmio_address) = mmio_read_by_4byte(mmio_address);
    } else if (8 == data_size) {
        *((uint64_t*)mmio_address) = mmio_read_by_8byte(mmio_address);
    } else {
        // ......
    }
}

int read_file_data(char* path,int* output_data) {
    int file_handle = open(path,O_RDONLY);

    if (-1 == file_handle)
        return 0;

    char temp_string[16] = {0};

    read(file_handle,temp_string,sizeof(temp_string));
    close(file_handle);
  
    char* no_use_string;
    *output_data = strtol(&temp_string,&no_use_string,16);

    return 1;
}

char* search_target_device(int device_id,int class_id,int vendor_id,int revision_id) {
    struct dirent* dirent_info = NULL;
    DIR* dir_info = opendir(LINUX_SYS_DEVICE_PATH);
    char temp_read_device_path[MAX_PATH];
    char temp_read_class_path[MAX_PATH];
    char temp_read_vendor_path[MAX_PATH];
    char temp_read_revision_path[MAX_PATH];

    while ((NULL != (dirent_info = readdir(dir_info)))) {
        if (dirent_info->d_type & DT_DIR) {
            int temp_device_id = 0;
            int temp_class_id = 0;
            int temp_vendor_id = 0;
            int temp_revision_id = 0;

            memset(temp_read_device_path,0,sizeof(temp_read_device_path));
            sprintf(temp_read_device_path,"%s/%s/device",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);
            memset(temp_read_class_path,0,sizeof(temp_read_class_path));
            sprintf(temp_read_class_path,"%s/%s/class",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);
            memset(temp_read_vendor_path,0,sizeof(temp_read_vendor_path));
            sprintf(temp_read_vendor_path,"%s/%s/vendor",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);
            memset(temp_read_revision_path,0,sizeof(temp_read_revision_path));
            sprintf(temp_read_revision_path,"%s/%s/revision",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);
            
            if (!read_file_data(temp_read_device_path,&temp_device_id) ||
                !read_file_data(temp_read_class_path,&temp_class_id) ||
                !read_file_data(temp_read_vendor_path,&temp_vendor_id) ||
                !read_file_data(temp_read_revision_path,&temp_revision_id))
                continue;

            if (device_id == temp_device_id &&
                class_id == temp_class_id &&
                vendor_id == temp_vendor_id &&
                revision_id == temp_revision_id) {
                char* result = (char*)malloc(MAX_PATH);
                memset(result,0,MAX_PATH);
                sprintf(result,"%s/%s/",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);

                return result;
            }
        }
    }
    
    return NULL;
}

char* get_device_name_by_id(int device_id,int class_id,int vendor_id,int revision_id) {
    for (int index = 0;index < fuzzer_device_table_count;++index)
        if (fuzzer_device_table[index].device_data.device_id == device_id &&
            fuzzer_device_table[index].device_data.class_id == class_id &&
            fuzzer_device_table[index].device_data.vendor_id == vendor_id &&
            fuzzer_device_table[index].device_data.revision_id == revision_id)
            return &fuzzer_device_table[index].device_name;
    
    return NULL;
}

device_register* get_device_register_map(char* device_name,int* output_device_register_size) {
    if (!strcmp("e1000",device_name)) {
        *output_device_register_size = e1000_register_size;

        return &e1000_register;
    }

    *output_device_register_size = 0;

    return NULL;
}


