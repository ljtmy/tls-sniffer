#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#define MAX_DATA_SIZE 4096

#define DIR_SEND 0
#define DIR_RECV 1

#define EVENT_DATA 0
#define EVENT_CONN_INFO 1

struct tls_event {
    __u64 timestamp;    // bpf_ktime_get_ns()
    __u32 pid;
    __u32 tid;
    __u32 data_len;
    __u32 direction;    // DIR_SEND or DIR_RECV
    __u64 ssl_ptr;      // SSL * pointer for partial read grouping
    __u32 event_type;   // EVENT_DATA or EVENT_CONN_INFO
    __u32 fd;           // socket fd (valid when event_type == EVENT_CONN_INFO)
    char comm[16];
    unsigned char data[MAX_DATA_SIZE];
};

// Per-tid state for uretprobe to recover entry params
struct read_state {
    void *buf;
    void *ssl;
};

#endif /* __SNIFFER_H__ */
