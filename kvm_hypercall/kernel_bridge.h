
#ifndef __KERNEL_BRIDGE_H__
#define __KERNEL_BRIDGE_H__

#define NETLINK_CHANNEL_ID 31

#define MSG_MAX_LENGTH 1024

#define MSG_ECHO "KVM Bridge Echo"

#define HYPERCALL_CHECK_FUZZER         (0xABCDEF)
#define HYPERCALL_CHECK_READY          (HYPERCALL_CHECK_FUZZER + 1)
#define HYPERCALL_PUSH_RECORD          (HYPERCALL_CHECK_FUZZER + 2)
#define HYPERCALL_GET_DEVICE           (HYPERCALL_CHECK_FUZZER + 3)
#define HYPERCALL_GET_CLASS            (HYPERCALL_CHECK_FUZZER + 4)
#define HYPERCALL_GET_VENDOR           (HYPERCALL_CHECK_FUZZER + 5)
#define HYPERCALL_GET_REVISION         (HYPERCALL_CHECK_FUZZER + 6)
#define HYPERCALL_GET_MMIO_RESOURCE    (HYPERCALL_CHECK_FUZZER + 7)
#define HYPERCALL_GET_PORTIO_RESOURCE  (HYPERCALL_CHECK_FUZZER + 8)

#define HYPERCALL_FLAG_SUCCESS              (0x0)
#define HYPERCALL_FLAG_FAIL                 (0x1)
#define HYPERCALL_FLAG_FAIL_FUZZER_OUTLINE  (0x2)
#define HYPERCALL_FLAG_FAIL_ERROR_ID        (0xFFFFFFFF)
#define HYPERCALL_FLAG_FAIL_UNSUPPORT       (-1)
#define HYPERCALL_FLAG_CHECK_FUZZER         (0x51464B4D)  //  string:'QFKM'

#define HYPERCALL_LOW_32BIT(HYPERCALL_RETURN_VALUE)  (HYPERCALL_RETURN_VALUE & 0xFFFFFFFF)
#define HYPERCALL_HIGH_32BIT(HYPERCALL_RETURN_VALUE) ((HYPERCALL_RETURN_VALUE >> 32) & 0xFFFFFFFF)


#ifndef __SANITIZE_CONVERAGE_H__
#ifdef __x86_64__
typedef uint64_t uint_t;
typedef float    ufloat;
#else
typedef uint32_t uint_t;
typedef float    ufloat;
#endif
#endif

#define KERNEL_BRIDGE_RESULT_ERROR     (0x00)
#define KERNEL_BRIDGE_RESULT_SUCCESS   (0x01)
#define KERNEL_BRIDGE_RESULT_DATA_TRAP (0x01)
#define KERNEL_BRIDGE_MESSAGE_ECHO     (0x10)
#define KERNEL_BRIDGE_MESSAGE_REGISTER (KERNEL_BRIDGE_MESSAGE_ECHO + 1)
#define KERNEL_BRIDGE_MESSAGE_BIND     (KERNEL_BRIDGE_MESSAGE_ECHO + 2)
#define KERNEL_BRIDGE_MESSAGE_ONLINE   (KERNEL_BRIDGE_MESSAGE_ECHO + 3)
#define KERNEL_BRIDGE_MESSAGE_RECORD   (KERNEL_BRIDGE_MESSAGE_ECHO + 4)
#define KERNEL_BRIDGE_MESSAGE_EXIT     (KERNEL_BRIDGE_MESSAGE_ECHO + 5)


typedef struct {
    int vm_pid;
    int device_id;
    int class_id;
    int vendor_id;
    int revision_id;
    int mmio_resource;
    int portio_resource;
} bind_target_data;

//  send to fuzzer.cc
typedef struct {
    int operation_id;
} kernel_message_header;

typedef struct {
    kernel_message_header header;
    int echo_buffer_length;
    char echo_buffer[MSG_MAX_LENGTH];
} kernel_message_echo;

typedef struct {
    kernel_message_header header;
} kernel_message_check_online;

typedef struct {
    kernel_message_header header;
    int vm_pid;
    int fuzzing_method;
    int fuzzing_size;
    int fuzzing_r1;
    int fuzzing_r2;
} kernel_message_record;


//  send to kvm_hypercall
typedef struct {
    int operation_id;
} user_message_header;

typedef struct {
    user_message_header header;
} user_message_echo;

typedef struct {
    user_message_header header;
    int pid;
} user_message_register_fuzzer;

typedef struct {
    user_message_header header;
    bind_target_data data;
} user_message_bind_target;

typedef struct {
    user_message_header header;
    int pid;
} user_message_check_online;




#endif
