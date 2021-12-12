
#ifndef __STUB_H__
#define __STUB_H__

//#define STUB_DEBUG_MODE

#define MAX_PATH (1024)

#define LINUX_SYS_DEVICE_PATH "/sys/devices/pci0000:00/"

void  mmio_write(memory_address mmio_address,void* data,int data_size);
void  mmio_read(memory_address mmio_address,int data_size);
char* search_target_device(int device_id,int class_id,int vendor_id,int revision_id);
device_register* get_device_register_map(char* device_name,int* output_device_register_size);

#endif
