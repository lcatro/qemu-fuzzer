
#ifndef __FUZZER_DEVICE_TABLE_H__
#define __FUZZER_DEVICE_TABLE_H__

#define MAX_DEVICE_NAME 256


#ifdef __KERNEL_BRIDGE_H__

typedef struct {
    char device_name[MAX_DEVICE_NAME];
    bind_target_data device_data;
} fuzzer_device;

extern fuzzer_device fuzzer_device_table[];
extern int fuzzer_device_table_count;

#endif

typedef struct {
    char register_name[MAX_DEVICE_NAME];
    int  register_offset;
    int  register_size;
} device_register;

extern device_register e1000_register[];
extern int e1000_register_size;


#endif
