
#include <asm/cacheflush.h>
#include <asm/vmx.h>
#include <asm/kvm_host.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <net/sock.h>


#if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
#include <linux/kprobes.h>
#else
#include <linux/kallsyms.h>
#endif

#include "kernel_bridge.h"

//#define ENABLE_VMCALL_LOG


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Access non-exported symbols");
MODULE_AUTHOR("Ben Bancroft");

static int (*buffervm_set_memory_rw)(unsigned long addr, int numpages);
static int (*buffervm_set_memory_ro)(unsigned long addr, int numpages);

static int (*vmcall_handle_func)(struct kvm_vcpu *vcpu);


#if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
static int handler_pre(struct kprobe *p, struct pt_regs *regs){
    return 0;
}
static struct kprobe kp = {  
    .symbol_name = "kallsyms_lookup_name",  
};  

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t fn_kallsyms_lookup_name = 0;

int __get_kallsyms_lookup_name(void)
{
    int ret = -1;
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);

    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);

        return ret;
    }

    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
    fn_kallsyms_lookup_name = (kallsyms_lookup_name_t)(void*)kp.addr;
    unregister_kprobe(&kp);
    return ret;
}
#endif

#define MAX_BIND 100
#define TARGET_UNBUSY 0
#define TARGET_BUSY   1

typedef struct {
    bind_target_data list[MAX_BIND];
    int busy_table[MAX_BIND];
    int using_bind_count;
} bind_target_list;

int fuzzer_pid = 0;
struct sock* netlink_handle = NULL;
struct mutex access_lock;
bind_target_list bind_target_table = {0};


static bind_target_data* save_bind_target(bind_target_data* input) {
    bind_target_data* result = NULL;
    int index;

    mutex_lock(&access_lock);

    for (index = 0;index < MAX_BIND;++index) {
        if (TARGET_BUSY == bind_target_table.busy_table[index])
            continue;

        memcpy(&bind_target_table.list[index],input,sizeof(bind_target_data));

        bind_target_table.using_bind_count += 1;
        bind_target_table.busy_table[index] = TARGET_BUSY;
        result = &bind_target_table.list[index];

        break;
    }

    mutex_unlock(&access_lock);

    return result;
}

static bind_target_data* get_bind_target(int vm_pid) {
    bind_target_data* result = NULL;
    int index;

    mutex_lock(&access_lock);

    for (index = 0;index < MAX_BIND;++index) {
        if (TARGET_UNBUSY == bind_target_table.busy_table[index] ||
            bind_target_table.list[index].vm_pid != vm_pid)
            continue;

        result = &bind_target_table.list[index];

        break;
    }

    mutex_unlock(&access_lock);

    return result;
}

static void clean_bind_target(int vm_pid) {
    mutex_lock(&access_lock);

    int index;

    for (index = 0;index < MAX_BIND;++index) {
        if (TARGET_UNBUSY == bind_target_table.busy_table[index] ||
            bind_target_table.list[index].vm_pid != vm_pid)
            continue;

        memset(&bind_target_table.list[index],0,sizeof(bind_target_data));

        bind_target_table.using_bind_count -= 1;
        bind_target_table.busy_table[index] = TARGET_UNBUSY;

        break;
    }

    mutex_unlock(&access_lock);
}

static void netlink_receive_recall(struct sk_buff* buffer) {  //  for fuzzer.cc
    struct nlmsghdr* message = (struct nlmsghdr*)buffer->data;
    user_message_header* recv_message_header = nlmsg_data(message);
    int operation_id = recv_message_header->operation_id;
    int pid = message->nlmsg_pid;
    struct sk_buff* output_buffer = nlmsg_new(MSG_MAX_LENGTH,0);
    struct nlmsghdr* message_header = NULL;
    kernel_message_echo* kernel_message_echo_ = NULL;
    kernel_message_header* kernel_message_header_ = NULL;
    user_message_bind_target* user_message_bind_target_ = NULL;
    NETLINK_CB(output_buffer).dst_group = 0;

    printk(KERN_INFO "netlink_receive_recall() operation_ID = %d\n",operation_id);

    switch (operation_id) {
        case KERNEL_BRIDGE_MESSAGE_ECHO:
            message_header = nlmsg_put(output_buffer,0,0,NLMSG_DONE,sizeof(kernel_message_echo),0);
            kernel_message_echo_ = (kernel_message_echo*)nlmsg_data(message_header);
            kernel_message_echo_->header.operation_id = operation_id;
            kernel_message_echo_->echo_buffer_length = strlen(MSG_ECHO);

            memcpy(&kernel_message_echo_->echo_buffer,MSG_ECHO,kernel_message_echo_->echo_buffer_length);
            printk(KERN_INFO "message_echo->echo_buffer_length = %d \n",kernel_message_echo_->echo_buffer_length);

            break;
        case KERNEL_BRIDGE_MESSAGE_REGISTER:
            message_header = nlmsg_put(output_buffer,0,0,NLMSG_DONE,sizeof(kernel_message_header),0);
            user_message_register_fuzzer* user_message_check_online = nlmsg_data(message);
            fuzzer_pid = user_message_check_online->pid;
            kernel_message_header_ = (kernel_message_header*)nlmsg_data(message_header);
            kernel_message_header_->operation_id = KERNEL_BRIDGE_RESULT_SUCCESS;

            printk(KERN_INFO "Update Fuzzer pid %d\n",fuzzer_pid);

            break;
        case KERNEL_BRIDGE_MESSAGE_BIND:
            user_message_bind_target_ = (user_message_bind_target*)recv_message_header;
            message_header = nlmsg_put(output_buffer,0,0,NLMSG_DONE,sizeof(kernel_message_header),0);
            kernel_message_header_ = (kernel_message_header*)nlmsg_data(message_header);

            if (NULL != save_bind_target(&user_message_bind_target_->data)) {
                kernel_message_header_->operation_id = KERNEL_BRIDGE_RESULT_SUCCESS;
                
                printk(KERN_INFO "Bind Target Success VM-PID=%d DeviceID=%X ClassID=%X\n",
                    user_message_bind_target_->data.vm_pid,
                    user_message_bind_target_->data.device_id,
                    user_message_bind_target_->data.class_id);
            } else {
                kernel_message_header_->operation_id = KERNEL_BRIDGE_RESULT_ERROR;

                printk(KERN_INFO "Bind Target Error\n");
            }

            break;
        default:
            message_header = nlmsg_put(output_buffer,0,0,NLMSG_DONE,sizeof(kernel_message_header),0);
            kernel_message_header_ = (kernel_message_header*)nlmsg_data(message_header);
            kernel_message_header_->operation_id = KERNEL_BRIDGE_RESULT_ERROR;

            printk(KERN_INFO "KVM_Hypercall Error Request Code => %d\n",operation_id);

            break;
    }

    int ret = nlmsg_unicast(netlink_handle,output_buffer,pid);
    printk(KERN_INFO "Netlink send back data to pid %d ,ret = %d\n",pid,ret);
}

#define GET_VMCALL_NUMBER(VALUE)     (VALUE = vcpu->arch.regs[VCPU_REGS_RAX])
#define GET_VMCALL_PARAMETER1(VALUE) (VALUE = vcpu->arch.regs[VCPU_REGS_RBX])
#define GET_VMCALL_PARAMETER2(VALUE) (VALUE = vcpu->arch.regs[VCPU_REGS_RCX])
#define GET_VMCALL_PARAMETER3(VALUE) (VALUE = vcpu->arch.regs[VCPU_REGS_RDX])
#define GET_VMCALL_PARAMETER4(VALUE) (VALUE = vcpu->arch.regs[VCPU_REGS_RSI])
#define GET_VMCALL_VM_PID(VALUE)     (VALUE = vcpu->kvm->userspace_pid)
#define SET_VMCALL_RESULT(VALUE)     (vcpu->arch.regs[VCPU_REGS_RAX] = VALUE)

static int buffervm_handle_vmcall(struct kvm_vcpu *vcpu) {  //  for stub.c
    uint_t vmcall_number;
    pid_t vm_pid;
    GET_VMCALL_NUMBER(vmcall_number);
    GET_VMCALL_VM_PID(vm_pid);

    #ifdef ENABLE_VMCALL_LOG
    printk("[%s] VM-PID %d vmcall: 0x%lx\n",__this_module.name,vm_pid,vmcall_number);
    #endif

    int result = (*vmcall_handle_func)(vcpu);
    int fuzzing_method,fuzzing_size,fuzzing_r1,fuzzing_r2;
    int device_info = 0;
    bind_target_data* bind_target_data_ = NULL;

    switch (vmcall_number) {
        case HYPERCALL_CHECK_FUZZER:
            #ifdef ENABLE_VMCALL_LOG
            printk(KERN_INFO "vmcall => HYPERCALL_CHECK_FUZZER \n");
            #endif
            SET_VMCALL_RESULT(HYPERCALL_FLAG_CHECK_FUZZER);

            break;
        case HYPERCALL_CHECK_READY:
            #ifdef ENABLE_VMCALL_LOG
            printk(KERN_INFO "vmcall => HYPERCALL_CHECK_READY \n");
            #endif
            SET_VMCALL_RESULT(HYPERCALL_FLAG_SUCCESS);
            
            break;
        case HYPERCALL_PUSH_RECORD:
            GET_VMCALL_PARAMETER1(fuzzing_method);
            GET_VMCALL_PARAMETER2(fuzzing_size);
            GET_VMCALL_PARAMETER3(fuzzing_r1);
            GET_VMCALL_PARAMETER4(fuzzing_r2);

            #ifdef ENABLE_VMCALL_LOG
            printk(KERN_INFO "vmcall => HYPERCALL_PUSH_RECORD fuzzing_method=%X fuzzing_size=%X %X %X\n",
                    fuzzing_method,
                    fuzzing_size,
                    fuzzing_r1,
                    fuzzing_r2);
            #endif

            if (fuzzer_pid && netlink_handle) {
                int buffer_size = sizeof(kernel_message_record);
                struct sk_buff* output_buffer = nlmsg_new(buffer_size,0);
                struct nlmsghdr* message_header = nlmsg_put(output_buffer,0,0,NLMSG_DONE,buffer_size,0);
                kernel_message_record* kernel_message_record_data = nlmsg_data(message_header);
                kernel_message_record_data->header.operation_id = KERNEL_BRIDGE_MESSAGE_RECORD;
                kernel_message_record_data->vm_pid = vm_pid;
                kernel_message_record_data->fuzzing_method = fuzzing_method;
                kernel_message_record_data->fuzzing_size = fuzzing_size;
                kernel_message_record_data->fuzzing_r1 = fuzzing_r1;
                kernel_message_record_data->fuzzing_r2 = fuzzing_r2;
                NETLINK_CB(output_buffer).dst_group = 0;
                nlmsg_unicast(netlink_handle,output_buffer,fuzzer_pid);
                SET_VMCALL_RESULT(HYPERCALL_FLAG_SUCCESS);
            } else {
                SET_VMCALL_RESULT(HYPERCALL_FLAG_FAIL_FUZZER_OUTLINE);
            }

            break;
        case HYPERCALL_GET_DEVICE:
            bind_target_data_ = (bind_target_data*)get_bind_target(vm_pid);
            
            if (NULL == bind_target_data_) {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_DEVICE Not-Found VM-PID=%d\n",vm_pid);
                #endif
                SET_VMCALL_RESULT(HYPERCALL_FLAG_FAIL_ERROR_ID);
            } else {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_DEVICE VM-PID=%d DeviceID=%d\n",
                    vm_pid,
                    bind_target_data_->device_id);
                #endif
                SET_VMCALL_RESULT(bind_target_data_->device_id);
            }

            break;
        case HYPERCALL_GET_CLASS:
            bind_target_data_ = (bind_target_data*)get_bind_target(vm_pid);
            
            if (NULL == bind_target_data_) {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_CLASS Not-Found VM-PID=%d\n",vm_pid);
                #endif
                SET_VMCALL_RESULT(HYPERCALL_FLAG_FAIL_ERROR_ID);
            } else {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_CLASS VM-PID=%d ClassID=%d\n",
                    vm_pid,
                    bind_target_data_->class_id);
                #endif
                SET_VMCALL_RESULT(bind_target_data_->class_id);
            }

            break;
        case HYPERCALL_GET_VENDOR:
            bind_target_data_ = (bind_target_data*)get_bind_target(vm_pid);
            
            if (NULL == bind_target_data_) {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_VENDOR Not-Found VM-PID=%d\n",vm_pid);
                #endif
                SET_VMCALL_RESULT(HYPERCALL_FLAG_FAIL_ERROR_ID);
            } else {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_VENDOR VM-PID=%d VendorID=%d\n",
                    vm_pid,
                    bind_target_data_->vendor_id);
                #endif
                SET_VMCALL_RESULT(bind_target_data_->vendor_id);
            }

            break;
        case HYPERCALL_GET_REVISION:
            bind_target_data_ = (bind_target_data*)get_bind_target(vm_pid);
            
            if (NULL == bind_target_data_) {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_REVISION Not-Found VM-PID=%d\n",vm_pid);
                #endif
                SET_VMCALL_RESULT(HYPERCALL_FLAG_FAIL_ERROR_ID);
            } else {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_REVISION VM-PID=%d RevisionID=%d\n",
                    vm_pid,
                    bind_target_data_->revision_id);
                #endif
                SET_VMCALL_RESULT(bind_target_data_->revision_id);
            }

            break;
        case HYPERCALL_GET_MMIO_RESOURCE:
            bind_target_data_ = (bind_target_data*)get_bind_target(vm_pid);
            
            if (NULL == bind_target_data_) {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_REVISION Not-Found VM-PID=%d\n",vm_pid);
                #endif
                SET_VMCALL_RESULT(HYPERCALL_FLAG_FAIL_ERROR_ID);
            } else {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_REVISION VM-PID=%d MMIO-ResouceID=%d\n",
                    vm_pid,
                    bind_target_data_->mmio_resource);
                #endif
                SET_VMCALL_RESULT(bind_target_data_->mmio_resource);
            }

            break;
        case HYPERCALL_GET_PORTIO_RESOURCE:
            bind_target_data_ = (bind_target_data*)get_bind_target(vm_pid);
            
            if (NULL == bind_target_data_) {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_REVISION Not-Found VM-PID=%d\n",vm_pid);
                #endif
                SET_VMCALL_RESULT(HYPERCALL_FLAG_FAIL_ERROR_ID);
            } else {
                #ifdef ENABLE_VMCALL_LOG
                printk(KERN_INFO "vmcall => HYPERCALL_GET_REVISION VM-PID=%d PortIO-ResourceID=%d\n",
                    vm_pid,
                    bind_target_data_->portio_resource);
                #endif
                SET_VMCALL_RESULT(bind_target_data_->portio_resource);
            }

            break;
        default:
            break;
    }

    return result;
}

static int __init buffervm_init(void)
{
    unsigned long addr;
    struct netlink_kernel_cfg init_config = {
        .input = netlink_receive_recall
    };

    netlink_handle = netlink_kernel_create(&init_net,NETLINK_CHANNEL_ID,&init_config);

    if (!netlink_handle) {
        pr_err("Create netlink Error no=%d\n",netlink_handle);
        
        return -ENXIO;
    }

    mutex_init(&access_lock);

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
        __get_kallsyms_lookup_name();

        buffervm_set_memory_rw = (void *)fn_kallsyms_lookup_name("set_memory_rw");
    #else
        buffervm_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw");
    #endif


    if (!buffervm_set_memory_rw) {
        pr_err("can't find set_memory_rw symbol\n");

        return -ENXIO;
    }

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
        buffervm_set_memory_ro = (void *)fn_kallsyms_lookup_name("set_memory_ro");
    #else
        buffervm_set_memory_ro = (void *)kallsyms_lookup_name("set_memory_ro");
    #endif

    if (!buffervm_set_memory_ro) {
        pr_err("can't find set_memory_ro symbol\n");

        return -ENXIO;
    }

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
        unsigned long handler_base_addr = fn_kallsyms_lookup_name("kvm_vmx_exit_handlers");
        uintptr_t vmcall_handle_func_symbol = fn_kallsyms_lookup_name("handle_vmcall");
    #else
        unsigned long handler_base_addr = kallsyms_lookup_name("kvm_vmx_exit_handlers");
        uintptr_t vmcall_handle_func_symbol = kallsyms_lookup_name("handle_vmcall");
    #endif

    uintptr_t *kvm_vmcall_exit_handler = (uintptr_t *)(handler_base_addr + sizeof (uintptr_t) * EXIT_REASON_VMCALL);


    if (*kvm_vmcall_exit_handler != vmcall_handle_func_symbol) {
        pr_err("Cannot patch vmcall handler - original function is wrong. Is kernel newer?\n");

        return -ENXIO;
    }

    vmcall_handle_func = vmcall_handle_func_symbol;

    printk(KERN_INFO "[%s] (0x%lx): 0x%lx actual 0x%lx\n", __this_module.name, handler_base_addr, *kvm_vmcall_exit_handler, vmcall_handle_func_symbol);

    addr = PAGE_ALIGN((uintptr_t) kvm_vmcall_exit_handler) - PAGE_SIZE;

    buffervm_set_memory_rw(addr, 1);
    *kvm_vmcall_exit_handler = &buffervm_handle_vmcall;
    buffervm_set_memory_ro(addr, 1);

    return 0;
}

static void __exit buffervm_exit(void)
{
    unsigned long addr;
    unsigned long handler_base_addr;
    uintptr_t *kvm_vmcall_exit_handler;

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
        handler_base_addr = (void *)fn_kallsyms_lookup_name("kvm_vmx_exit_handlers");
    #else
        handler_base_addr = (void *)kallsyms_lookup_name("kvm_vmx_exit_handlers");
    #endif
        
    kvm_vmcall_exit_handler = (uintptr_t *)(handler_base_addr + sizeof (uintptr_t) * EXIT_REASON_VMCALL);
    addr = PAGE_ALIGN((uintptr_t) kvm_vmcall_exit_handler) - PAGE_SIZE;

    buffervm_set_memory_rw(addr, 1);
    *kvm_vmcall_exit_handler = vmcall_handle_func;
    buffervm_set_memory_ro(addr, 1);

    netlink_kernel_release(netlink_handle);
    mutex_unlock(&access_lock);

    printk(KERN_INFO "Goodbye world 1.\n");
}

module_init(buffervm_init);
module_exit(buffervm_exit);
