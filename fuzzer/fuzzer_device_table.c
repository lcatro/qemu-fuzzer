
#include <inttypes.h>
#include <stdint.h>

#include "kernel_bridge.h"
#include "fuzzer_device_table.h"


fuzzer_device fuzzer_device_table[] = {
    /* vm_pid,device_id,class_id,vendor_id,revision_id,mmio_resource,portio_resource */
    {"vuln-device",{0x00,0x6666,0xFF00,0x1234,0x00,0x00,HYPERCALL_FLAG_FAIL_UNSUPPORT}} ,
    {"usb-ehci",{0x00,0x24CD,0xC0320,0x8086,0x10,0x00,HYPERCALL_FLAG_FAIL_UNSUPPORT}} ,
    {"usb-ohci",{0x00,0x24CD,0xC0310,0x8086,0x10,0x00,HYPERCALL_FLAG_FAIL_UNSUPPORT}} ,
    {"sdhci-pci",{0x00,0x0007,0x080501,0x1B36,0x00,0x00,HYPERCALL_FLAG_FAIL_UNSUPPORT}} ,
    {"e1000",{0x00,0x100e,0x020000,0x8086,0x03,0x00,HYPERCALL_FLAG_FAIL_UNSUPPORT}} ,
    {"e1000e",{0x00,0x10d3,0x020000,0x8086,0x00,0x00,HYPERCALL_FLAG_FAIL_UNSUPPORT}} ,
    {"ati-vga",{0x00,0x5046,0x030000,0x1002,0x00,0x00,HYPERCALL_FLAG_FAIL_UNSUPPORT}} ,
};
int fuzzer_device_table_count = sizeof(fuzzer_device_table) / sizeof(fuzzer_device);

