//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "sniffer.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// PID filter: key=pid, value=1. If filter_enabled[0]==1, only PIDs in this map pass through.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} pid_filter SEC(".maps");

// Flag: filter_enabled[0] = 1 means PID filtering is active
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} filter_enabled SEC(".maps");

// Store entry params for uretprobe (key=tid, value=read_state)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct read_state);
} read_entries SEC(".maps");

static __always_inline int filter_active(void)
{
    __u32 key = 0;
    __u8 *val = bpf_map_lookup_elem(&filter_enabled, &key);
    return val && *val;
}

static __always_inline int should_capture(__u32 pid)
{
    if (!filter_active())
        return 1;
    __u32 key = pid;
    return bpf_map_lookup_elem(&pid_filter, &key) != NULL;
}

static __always_inline void submit_event(struct pt_regs *ctx,
    void *buf, __u32 len, __u32 direction, void *ssl)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    if (!should_capture(pid))
        return;

    if (len == 0)
        return;

    struct tls_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->direction = direction;
    event->ssl_ptr = (__u64)(unsigned long)ssl;
    event->event_type = EVENT_DATA;
    event->fd = 0;

    __u32 read_len = len;
    if (read_len > MAX_DATA_SIZE)
        read_len = MAX_DATA_SIZE;
    event->data_len = read_len;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user(event->data, read_len, buf);

    bpf_ringbuf_submit(event, 0);
}

// --- SSL_write: uprobe (entry) ---
// SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe/ssl_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0)
        return 0;

    submit_event(ctx, buf, num, DIR_SEND, ssl);
    return 0;
}

// --- SSL_write_ex: uprobe (entry) ---
// SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
SEC("uprobe/ssl_write_ex")
int uprobe_ssl_write_ex(struct pt_regs *ctx)
{
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t num = (size_t)PT_REGS_PARM3(ctx);

    if (num == 0)
        return 0;

    submit_event(ctx, buf, num, DIR_SEND, ssl);
    return 0;
}

// --- SSL_read: uprobe (entry) ---
// Save buf and ssl pointer for uretprobe to read data after return
SEC("uprobe/ssl_read")
int uprobe_ssl_read(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_state state = {
        .buf = (void *)PT_REGS_PARM2(ctx),
        .ssl = (void *)PT_REGS_PARM1(ctx),
    };
    bpf_map_update_elem(&read_entries, &tid, &state, BPF_ANY);
    return 0;
}

// --- SSL_read: uretprobe (return) ---
// Read the filled buffer using the saved entry params
SEC("uretprobe/ssl_read")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_state *state = bpf_map_lookup_elem(&read_entries, &tid);
    if (!state)
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    void *buf = state->buf;
    void *ssl = state->ssl;

    bpf_map_delete_elem(&read_entries, &tid);

    if (ret <= 0)
        return 0;

    submit_event(ctx, buf, ret, DIR_RECV, ssl);
    return 0;
}

// --- SSL_read_ex: uprobe (entry) ---
// SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
SEC("uprobe/ssl_read_ex")
int uprobe_ssl_read_ex(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_state state = {
        .buf = (void *)PT_REGS_PARM2(ctx),
        .ssl = (void *)PT_REGS_PARM1(ctx),
        .readbytes = (void *)PT_REGS_PARM4(ctx),
    };
    bpf_map_update_elem(&read_entries, &tid, &state, BPF_ANY);
    return 0;
}

// --- SSL_read_ex: uretprobe (return) ---
SEC("uretprobe/ssl_read_ex")
int uretprobe_ssl_read_ex(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_state *state = bpf_map_lookup_elem(&read_entries, &tid);
    if (!state)
        return 0;

    // SSL_read_ex returns 1 on success, 0 on failure
    int ret = (int)PT_REGS_RC(ctx);
    void *ssl = state->ssl;

    // Use the saved readbytes pointer from entry, not PARM4 which is invalid at return
    size_t readbytes = 0;
    if (state->readbytes)
        bpf_probe_read_user(&readbytes, sizeof(readbytes), state->readbytes);

    void *buf = state->buf;

    bpf_map_delete_elem(&read_entries, &tid);

    if (ret != 1 || readbytes == 0)
        return 0;

    submit_event(ctx, buf, readbytes, DIR_RECV, ssl);
    return 0;
}

// --- SSL_set_fd: uprobe (entry) ---
// SSL_set_fd(SSL *ssl, int fd) — capture the ssl→fd mapping for connection tracking
SEC("uprobe/ssl_set_fd")
int uprobe_ssl_set_fd(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!should_capture(pid))
        return 0;

    void *ssl = (void *)PT_REGS_PARM1(ctx);
    int fd = (int)PT_REGS_PARM2(ctx);

    struct tls_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (__u32)pid_tgid;
    event->direction = 0;
    event->ssl_ptr = (__u64)(unsigned long)ssl;
    event->event_type = EVENT_CONN_INFO;
    event->fd = fd;
    event->data_len = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// --- gnutls_record_send: uprobe (entry) ---
// gnutls_record_send(gnutls_session_t session, const void *data, size_t data_size)
SEC("uprobe/gnutls_send")
int uprobe_gnutls_send(struct pt_regs *ctx)
{
    void *session = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t num = (size_t)PT_REGS_PARM3(ctx);

    submit_event(ctx, buf, num, DIR_SEND, session);
    return 0;
}

// --- gnutls_record_recv: uprobe (entry) ---
// Save session and buf for uretprobe
SEC("uprobe/gnutls_recv")
int uprobe_gnutls_recv(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_state state = {
        .buf = (void *)PT_REGS_PARM2(ctx),
        .ssl = (void *)PT_REGS_PARM1(ctx),
    };
    bpf_map_update_elem(&read_entries, &tid, &state, BPF_ANY);
    return 0;
}

// --- gnutls_record_recv: uretprobe (return) ---
SEC("uretprobe/gnutls_recv")
int uretprobe_gnutls_recv(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_state *state = bpf_map_lookup_elem(&read_entries, &tid);
    if (!state)
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    void *buf = state->buf;
    void *session = state->ssl;

    bpf_map_delete_elem(&read_entries, &tid);

    if (ret <= 0)
        return 0;

    submit_event(ctx, buf, ret, DIR_RECV, session);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
