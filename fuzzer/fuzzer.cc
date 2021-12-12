
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <malloc.h>
#include <memory.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <map>
#include <string>
#include <vector>

#include "kernel_bridge.h"
#include "sanitize_converage.h"
#include "signal_number.h"

#include "fuzzer_device_table.h"
#include "fuzzer_mutite.h"

#define MAX_FUZZER_READ_PIPE_DATA_SIZE (10 * 1024)
#define MAX_FUZZER_SUBPROCESS 5


using namespace std;


class subprocess_fuzz_function {
    public:
        subprocess_fuzz_function() {}

        subprocess_fuzz_function(uint_t function_address,uint_t function_edge_count) {
            this->function_address = function_address;
            this->function_edge_count = function_edge_count;
        }

        bool is_exist_edge_id(uint_t edge_id) {
            for (auto iterator = this->function_execute_edge_list.begin();
                 iterator != this->function_execute_edge_list.end();
                 ++iterator) {
                if (*iterator == edge_id)
                    return true;
            }

            return false;
        }

        void add_execute_edge(uint_t edge_id) {
            if (this->is_exist_edge_id(edge_id))
                return;

            this->function_execute_edge_list.push_back(edge_id);
        }

        uint_t get_function_address(void) {
            return this->function_address;
        }

        uint_t get_function_edge_count(void) {
            return this->function_edge_count;
        }

        uint_t get_function_execute_edge_count(void) {
            return this->function_execute_edge_list.size();
        }

    private:
        uint_t function_address;
        uint_t function_edge_count;
        std::vector<uint_t> function_execute_edge_list;
};

class subprocess_fuzz_process {
    public:
        subprocess_fuzz_process() {}

        bool is_exist_function(uint_t function_address) {
            if (this->process_function_table.count(function_address))
                return true;

            return false;
        }

        void add_function(uint_t function_address,uint_t function_edge_count) {
            if (this->is_exist_function(function_address))
                return;

            subprocess_fuzz_function new_object(function_address,function_edge_count);

            this->process_function_table[function_address] = new_object;
        }

        void add_function_execute_edge(uint_t function_address,uint_t edge_id) {
            this->process_function_table[function_address].add_execute_edge(edge_id);
        }

        uint_t get_function_count() {
            return this->process_function_table.size();
        }

        uint_t get_edge_count() {
            uint_t edge_count = 0;

            for (auto iterator = this->process_function_table.begin();
                 iterator != this->process_function_table.end();
                 ++iterator)
                edge_count += iterator->second.get_function_edge_count();

            return edge_count;
        }

        uint_t get_execute_edge_count() {
            uint_t execute_edge_count = 0;

            for (auto iterator = this->process_function_table.begin();
                 iterator != this->process_function_table.end();
                 ++iterator)
                execute_edge_count += iterator->second.get_function_execute_edge_count();

            return execute_edge_count;
        }

        ufloat get_coverage_rate() {
            uint_t edge_count = this->get_edge_count();
            uint_t execute_edge_count = this->get_execute_edge_count();

            return ((ufloat)execute_edge_count / (ufloat)edge_count) * 100;
        }

    private:
        std::map<uint_t,subprocess_fuzz_function> process_function_table;
};

class subprocess_envirement {
    public:
        subprocess_envirement(uint_t pid,uint_t start_time) {
            this->start_time = start_time;
            this->pid = pid;
        }

        uint_t get_pid(void) {
            return this->pid;
        }

        uint_t get_start_time(void) {
            return this->start_time;
        }

        subprocess_fuzz_process fuzz_static;

    private:
        uint_t pid;
        uint_t start_time;
};

class subprocess_envirement_list {
    public:
        subprocess_envirement_list() {}

        bool is_exist(uint_t pid) {
            for (auto iterator = list_data.begin();
                 iterator != list_data.end();
                 ++iterator) {
                if (iterator->get_pid() == pid)
                    return true;
            }

            return false;
        }

        subprocess_envirement* get_by_pid(uint_t pid) {
            for (auto iterator = list_data.begin();
                 iterator != list_data.end();
                 ++iterator) {
                if (iterator->get_pid() == pid)
                    return (subprocess_envirement*)&*iterator;
            }
            
            return NULL;
        }

        void add_record(uint_t pid,uint_t start_time) {
            subprocess_envirement new_object(pid,start_time);

            list_data.push_back(new_object);
        }

    private:
        std::vector<subprocess_envirement> list_data;
};


subprocess_envirement_list subprocess_envirement_table;
int current_all_sub_fuzzer = 0;
pid_t current_fuzzer_pid = 0;


void signal_handler(int signal_code,siginfo_t *singnal_info,void *p) {
    //if (SIGUSR1 != signal_code)
    //    return;

    int parameter = singnal_info->si_value.sival_int;
    int subprocess_pid = singnal_info->si_pid;

    switch (signal_code) {
        case SIGNAL_CREATE_FUZZER_TARGET: {
            //  parameter  =>  pid
            int pid = parameter;
            
            printf("Create SubProcess Success ==> PID:%d \n",subprocess_pid);

            subprocess_envirement_table.add_record(subprocess_pid,time(NULL));

            current_all_sub_fuzzer++;

            break;
        } case SIGNAL_FUZZ_ONCE: {
            //  parameter  =>  fuzz_index
            int trace_round_id = parameter;

            printf("SubProcess Fuzz ==> PID:%d TraceRoundID:%d \n",subprocess_pid,trace_round_id);

            subprocess_envirement* subprocess_data = subprocess_envirement_table.get_by_pid(subprocess_pid);

            if (NULL == subprocess_data) {
                printf("Catch Error PID !! \n");

                return;
            }

            char save_coverage_path[MAX_PATH_SIZE] = {0};

            sprintf(save_coverage_path,"./temp_%d_%d/%d.dat",current_fuzzer_pid,subprocess_pid,trace_round_id);

            int save_data_handle = open(save_coverage_path,O_RDONLY);
            struct stat file_state = {0};

            fstat(save_data_handle, &file_state);

            if (!file_state.st_size) {
                printf("Coverage Data %s is empty \n",save_coverage_path);
                close(save_data_handle);

                return;
            }

            uint_t trace_pc_map_count = 0;

            read(save_data_handle,&trace_pc_map_count,sizeof(uint_t));

            uint_t coverage_result_size = file_state.st_size - sizeof(uint_t);
            __sancov_trace_pc_map* coverage_result = (__sancov_trace_pc_map*)malloc(coverage_result_size);
            uint_t read_offset = 0;
            int read_length = 0;

            memset(coverage_result,0,coverage_result_size);

            while ((read_length = read(save_data_handle,
                                        &((unsigned char*)coverage_result)[read_offset],
                                        MAX_FUZZER_READ_PIPE_DATA_SIZE)) > 0) {
                read_offset += read_length;
            }

            subprocess_fuzz_process fuzz_static = subprocess_envirement_table.get_by_pid(subprocess_pid)->fuzz_static;

            for (uint_t index = 0;index < trace_pc_map_count;++index) {
                /*
                printf("%d Coverage ID %X (%X) ,Count %d\n",index,
                        coverage_result[index].current_edge_id,
                        coverage_result[index].current_function_entry,
                        coverage_result[index].current_function_edge_count);
                        */

                fuzz_static.add_function(coverage_result[index].current_function_entry,
                    coverage_result[index].current_function_edge_count);
                fuzz_static.add_function_execute_edge(coverage_result[index].current_function_entry,
                    coverage_result[index].current_edge_id);
            }

            printf("Fuzz Static :\n");
            printf("  Function Count %d\n",fuzz_static.get_function_count());
            printf("  Execute Edge Count %d\n",fuzz_static.get_execute_edge_count());
            printf("  Coverage Edge Count %d\n",fuzz_static.get_edge_count());
            printf("  Coverage Rate %.2f%%\n",fuzz_static.get_coverage_rate());

            free(coverage_result);
            close(save_data_handle);
            remove(save_coverage_path);  //  << disk killer

            break;
        } default: {
            printf("Error Status Code ==> PID:%d \n",subprocess_pid);
        }

    }
}

pthread_mutex_t thread_lock;
int socket_handle;

void netlink_create(void) {
    socket_handle = socket(PF_NETLINK,SOCK_RAW,NETLINK_CHANNEL_ID);

    if(socket_handle < 0) {
        printf("Create Netlink Socket Error !\n");
        exit(1);
    }

    sockaddr_nl user = {0};
    timeval receive_timeout = {3,0};  //  block wait 3s

    memset(&user,0,sizeof(user));

    user.nl_family = AF_NETLINK;
    user.nl_pid = getpid();

    bind(socket_handle,(struct sockaddr*)&user,sizeof(user));
    //setsockopt(socket_handle,SOL_SOCKET,SO_RCVTIMEO,(char *)&receive_timeout,sizeof(struct timeval));
}

void netlink_send(int socket_handle,void* send_buffer,int send_buffer_size) {
    sockaddr_nl kernel;

    memset(&kernel,0,sizeof(kernel));

    kernel.nl_family = AF_NETLINK;
    kernel.nl_pid = 0;
    kernel.nl_groups = 0;

    struct nlmsghdr* message_header_send = (struct nlmsghdr*)malloc(NLMSG_SPACE(send_buffer_size));
    memset(message_header_send,0,NLMSG_SPACE(send_buffer_size));
    message_header_send->nlmsg_len = NLMSG_SPACE(send_buffer_size);
    message_header_send->nlmsg_pid = getpid();
    message_header_send->nlmsg_flags = 0;

    memcpy((void*)NLMSG_DATA(message_header_send),send_buffer,send_buffer_size);

    struct iovec iov_send = {
        .iov_base = (void *)message_header_send,
        .iov_len = message_header_send->nlmsg_len
    };

    struct msghdr message_data_send = {
        .msg_name = (void *)&kernel,
        .msg_namelen = sizeof(kernel),
        .msg_iov = &iov_send,
        .msg_iovlen = 1
    };

    sendmsg(socket_handle, &message_data_send, 0);

    free(message_header_send);
}

nlmsghdr* netlink_recv(int socket_handle) {
    sockaddr_nl kernel;

    memset(&kernel,0,sizeof(kernel));

    kernel.nl_family = AF_NETLINK;
    kernel.nl_pid = 0;
    kernel.nl_groups = 0;

    struct nlmsghdr* message_header_recv = (struct nlmsghdr*)malloc(NLMSG_SPACE(MSG_MAX_LENGTH));
    memset(message_header_recv, 0, NLMSG_SPACE(MSG_MAX_LENGTH));
    message_header_recv->nlmsg_len = NLMSG_SPACE(MSG_MAX_LENGTH);
    message_header_recv->nlmsg_pid = getpid();
    message_header_recv->nlmsg_flags = 0;

    struct iovec iov_receive = {
        .iov_base = (void *)message_header_recv,
        .iov_len = message_header_recv->nlmsg_len
    };
    struct msghdr message_data_receive = {
        .msg_name = (void *)&kernel,
        .msg_namelen = sizeof(kernel),
        .msg_iov = &iov_receive,
        .msg_iovlen = 1
    };

    if (-1 == recvmsg(socket_handle,&message_data_receive,0)) {
        free(message_header_recv);

        return NULL;
    }
    
    return message_header_recv;
}

void* thread_fuzz_monitor(void* argement) {
    //  Step1: Check kvm_hypercall_bridge 
    user_message_header echo_test;

    echo_test.operation_id = KERNEL_BRIDGE_MESSAGE_ECHO;

    netlink_send(socket_handle,(void*)&echo_test,sizeof(echo_test));

    nlmsghdr* message_header_recv = netlink_recv(socket_handle);

    if (NULL == message_header_recv) {
        printf("Kernel KVM_Bridge Not Exist!");
        exit(1);
    }

    kernel_message_header* kernel_message_header_ = (kernel_message_header*)NLMSG_DATA(message_header_recv);

    if (KERNEL_BRIDGE_MESSAGE_ECHO != kernel_message_header_->operation_id) {
        printf("KVM_Bridge Echo Error!");
        exit(1);
    }

    kernel_message_echo* kernel_message_echo_ = (kernel_message_echo*)kernel_message_header_;

    printf("KVM_Hypercall Echo => %s\n",kernel_message_echo_->echo_buffer);
    free(message_header_recv);

    //  Step2 :Register kvm_hypercall_bridge 
    user_message_register_fuzzer register_data = {0};
    register_data.header.operation_id = KERNEL_BRIDGE_MESSAGE_REGISTER;
    register_data.pid = getpid();

    netlink_send(socket_handle,(void*)&register_data,sizeof(register_data));

    message_header_recv = netlink_recv(socket_handle);

    if (NULL == message_header_recv) {
        printf("Receive Register Message Error!");
        exit(1);
    }

    kernel_message_header_ = (kernel_message_header*)NLMSG_DATA(message_header_recv);

    if (KERNEL_BRIDGE_RESULT_SUCCESS != kernel_message_header_->operation_id) {
        printf("KVM_Bridge Register Fuzzer Error!");
        exit(1);
    }

    printf("KVM_Hypercall Register => Success\n");
    free(message_header_recv);

    //  Step3 :Loop for kvm_vmcall_record
    while (1) {
        message_header_recv = netlink_recv(socket_handle);

        if (NULL == message_header_recv) {
            printf("Loop Receive KVM vmcall Message Error!");

            continue;
        }

        kernel_message_header_ = (kernel_message_header*)NLMSG_DATA(message_header_recv);

        if (KERNEL_BRIDGE_MESSAGE_RECORD != kernel_message_header_->operation_id) {
            printf("Drop No Record Message! \n");
            free(message_header_recv);

            continue;
        }

        kernel_message_record* kernel_message_record_data = \
            (kernel_message_record*)NLMSG_DATA(message_header_recv);
        int fuzz_entry = GET_FUZZ_ENTRY(kernel_message_record_data->fuzzing_method);
        int fuzz_io = GET_FUZZ_IO(kernel_message_record_data->fuzzing_method);
        int fuzz_offset = GET_FUZZ_OFFSET(kernel_message_record_data->fuzzing_method);

        printf("VM(%d) Fuzzing Data:%d %d %X %d %X %X\n",
            kernel_message_record_data->vm_pid,
            fuzz_entry,
            fuzz_io,
            fuzz_offset,
            kernel_message_record_data->fuzzing_size,
            kernel_message_record_data->fuzzing_r1,
            kernel_message_record_data->fuzzing_r2);
        free(message_header_recv);
    }

    close(socket_handle);

    pthread_mutex_lock(&thread_lock);
    pthread_mutex_unlock(&thread_lock);


    return 0;
}

fuzzer_device* get_device_infomation(char* device_name) {
    for (int index = 0;index < fuzzer_device_table_count;++index)
        if (!strcmp(fuzzer_device_table[index].device_name,device_name))
            return &fuzzer_device_table[index];

    return NULL;
}

int main(int argc,char** argv) {
    if (2 > argc) {
        printf("Using: fuzzer %%detect_elf_path%% %%qemu_command_argument%% \n");

        return 1;
    }

    int device_flag = 1;

    for (;device_flag < argc;++device_flag) {
        if (!strcmp("-device",argv[device_flag])) {
            device_flag += 1;

            break;
        }
    }

    if (argc <= device_flag) {
        printf("Fuzzer can't not found -device option\n");

        return 1;
    }

    char* device_name = argv[device_flag];
    fuzzer_device* device_info = get_device_infomation(device_name);

    if (NULL == device_info) {
        printf("Ops ,this device(%s) no information\n",device_name);

        return 1;
    }

    printf("Fuzzer Load Device %s \n",&device_info->device_name);
    netlink_create();
    pthread_mutex_init(&thread_lock, NULL);

    pthread_t thread_data;
    pthread_create(&thread_data,NULL,thread_fuzz_monitor,NULL);

    struct sigaction action;
    action.sa_sigaction = signal_handler;
    action.sa_flags = SA_SIGINFO;

    sigemptyset(&action.sa_mask);

    if(sigaction(SIGNAL_CREATE_FUZZER_TARGET,&action,NULL) < 0) {
        printf("sigaction error!\n");
        _exit(-1);
    }

    if(sigaction(SIGNAL_FUZZ_ONCE,&action,NULL) < 0) {
        printf("sigaction error!\n");
        _exit(-1);
    }

    printf("fuzzer pid = %d \n",getpid());

    char* execute_path = argv[1];
    int pid = fork();

    if (!pid) {  //  Qemu Process
        //  Step 4: Update Qemu Process Device Infomation for Stub
        user_message_bind_target device_data = {0};

        memcpy(&device_data.data,&device_info->device_data,sizeof(bind_target_data));

        device_data.header.operation_id = KERNEL_BRIDGE_MESSAGE_BIND;
        device_data.data.vm_pid = getpid();

        netlink_send(socket_handle,&device_data,sizeof(bind_target_data));

        if (2 == argc) {
            execl(execute_path,NULL);
        } else {
            execvp(execute_path,&argv[1]);
        }
    } else {  //  Fuzzer monitor
        int status;
        current_fuzzer_pid = getpid();

        while(waitpid(pid, &status, 0) < 0);

        printf("Fuzzer Exit! \n");
    }

    return 0;
}


