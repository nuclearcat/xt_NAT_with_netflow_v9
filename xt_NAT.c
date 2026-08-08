#include <linux/module.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include "compat.h"
#include "xt_NAT.h"

#define FLAG_REPLIED   (1 << 0) /* 000001 */
#define FLAG_TCP_FIN   (1 << 1) /* 000010 */

#define TCP_SYN_ACK 0x12
#define TCP_FIN_RST 0x05

/* the GC timers walk 1/100th and 1/60th of the tables per tick, so a table
 * smaller than that has slices of zero buckets and never ages anything out */
#define NAT_HASH_MIN 1024
#define NAT_HASH_MAX (1 << 24)

#define USER_MAX_SESSIONS_DEF 4096

static LIST_HEAD(usock_list);
static int sndbuf = 1310720;
static int flowsetID = 300;
static unsigned int pdu_data_records = 0;
static unsigned int pdu_seq = 0;
struct netflow9_pdu pdu;
struct netflow9_template templateV9;
static DEFINE_SPINLOCK(nfsend_lock);

/* Counters touched during normal operation, per CPU. As shared atomic64 these
 * were three bounces of the same cacheline for every session created and a
 * fourth for every one freed, across every CPU at once - the exact shape of
 * cost that has been dominating this module. The failure counters below stay
 * atomic64: they only fire on error paths, where a contended cacheline is not
 * the problem.
 *
 * active is inc'd by the CPU creating a session and dec'd by whichever CPU
 * runs the GC, so a single CPU's value can go negative; only the sum across
 * CPUs is meaningful, which is why it is signed.
 */
struct nat_pcpu_stats {
    u64 tried;
    u64 created;
    u64 dup;
    u64 dnat_dropped;
    u64 frags;
    u64 related_icmp;
    s64 active;
};
static DEFINE_PER_CPU(struct nat_pcpu_stats, nat_pcpu_stats);

#define NAT_STAT_INC(f) this_cpu_inc(nat_pcpu_stats.f)
#define NAT_STAT_DEC(f) this_cpu_dec(nat_pcpu_stats.f)

static s64 nat_stat_sum(size_t off)
{
    s64 total = 0;
    int cpu;

    for_each_possible_cpu(cpu)
        total += *(s64 *)((char *)per_cpu_ptr(&nat_pcpu_stats, cpu) + off);
    return total;
}
#define NAT_STAT_READ(f) nat_stat_sum(offsetof(struct nat_pcpu_stats, f))

static atomic64_t users_active = ATOMIC_INIT(0);

/* Drop accounting. Every one of these used to be a printk on the packet path,
 * which meant a flood of malformed packets - or simply a NAT address running
 * out of ports - turned into a log storm that cost far more than the drop.
 * Counters instead: they are on the error paths only, so a shared atomic is
 * cheap enough, and they are what you actually want when the box hits a limit.
 */
static atomic64_t pkt_drop_proto = ATOMIC_INIT(0);
static atomic64_t pkt_drop_hdrlen = ATOMIC_INIT(0);
static atomic64_t pkt_drop_frag = ATOMIC_INIT(0);
static atomic64_t pkt_drop_trunc = ATOMIC_INIT(0);
static atomic64_t pkt_drop_unwritable = ATOMIC_INIT(0);
static atomic64_t pkt_drop_nosession = ATOMIC_INIT(0);
static atomic64_t ses_fail_ulimit = ATOMIC_INIT(0);
static atomic64_t ses_fail_noport = ATOMIC_INIT(0);
static atomic64_t ses_fail_nomem = ATOMIC_INIT(0);

static char nat_pool_buf[128] = "127.0.0.1-127.0.0.1";
static char *nat_pool = nat_pool_buf;
module_param(nat_pool, charp, 0444);
MODULE_PARM_DESC(nat_pool, "NAT pool range (addr_start-addr_end), default = 127.0.0.1-127.0.0.1");

static int nat_hash_size = 256 * 1024;
module_param(nat_hash_size, int, 0444);
MODULE_PARM_DESC(nat_hash_size, "nat hash size, default = 256k");

static int users_hash_size = 64 * 1024;
module_param(users_hash_size, int, 0444);
MODULE_PARM_DESC(users_hash_size, "users hash size, default = 64k");

/* Per-user session cap, per protocol. Was hardcoded at 4096 in three places
 * while the README advertised 1000. Mode 0644, so it is writable at runtime
 * through /sys/module/xt_NAT/parameters/user_max_sessions without needing a
 * /proc write path. The per-user counters are uint16_t, so values above
 * USHRT_MAX cannot be represented and are clamped where it is read.
 */
static int user_max_sessions = USER_MAX_SESSIONS_DEF;
module_param(user_max_sessions, int, 0644);
MODULE_PARM_DESC(user_max_sessions,
                 "max sessions per user per protocol (1-65535), default = 4096");

static char nf_dest_buf[128] = "";
static char *nf_dest = nf_dest_buf;
module_param(nf_dest, charp, 0444);
MODULE_PARM_DESC(nf_dest, "Netflow v9 collectors (addr1:port1[,addr2:port2]), default = none");

u_int32_t nat_htable_vector = 0;
u_int32_t users_htable_vector = 0;

static spinlock_t *create_session_lock;

static DEFINE_SPINLOCK(sessions_timer_lock);
static DEFINE_SPINLOCK(users_timer_lock);
static struct timer_list sessions_cleanup_timer, users_cleanup_timer, nf_send_timer;

/* All three timers re-arm themselves from their own callback, so
 * del_timer_sync() alone is not enough to stop them - the caller has to
 * prevent the restart first. NONE means the timers were never set up, so
 * teardown after a failed init must not touch them.
 */
#define NAT_TIMERS_NONE 0
#define NAT_TIMERS_RUN  1
#define NAT_TIMERS_STOP 2
static atomic_t timers_state = ATOMIC_INIT(NAT_TIMERS_NONE);

struct proc_dir_entry *proc_net_nat;

struct netflow_sock {
    struct list_head list;
    struct socket *sock;
    struct sockaddr_storage addr;   // destination
};

struct xt_nat_htable {
    uint32_t use;
    spinlock_t lock;
    struct hlist_head session;
};

/* One object per session, linked into both hash tables at once. 64 bytes -
 * exactly one cacheline, so a lookup touches a single line rather than an
 * entry plus a pointer chase to a second object elsewhere in memory. This was
 * three allocations totalling 152 bytes.
 *
 * The union is what makes it fit. rcu_head is only used once the session has
 * been unlinked from both tables and can no longer be found by anyone, and the
 * only fields it overlays are the NetFlow destination - which the GC reads for
 * the session-close record one sweep *before* the unlink. No reader in the
 * packet path or in /proc ever looks at dst, so none can see it overwritten.
 * Overlaying anything else here would be a use-after-free.
 */
struct nat_session {
    union {
        struct rcu_head rcu;            /* valid only after the final unlink */
        struct {
            uint32_t addr;              /* NetFlow: original destination */
            uint16_t port;
        } dst;
    } u;
    struct hlist_node inner_node;       /* keyed (proto, in_addr, in_port)   */
    struct hlist_node outer_node;       /* keyed (proto, nat_addr, out_port) */
    uint32_t in_addr;
    uint32_t nat_addr;
    uint16_t in_port;
    uint16_t out_port;
    int16_t  timeout;
    uint8_t  proto;
    uint8_t  flags;
};

/* A private cache, not the shared kmalloc pool: sessions are allocated and
 * freed constantly and in large numbers, and interleaving them with every
 * other kernel user of that size means freeing them returns few whole slabs.
 * At exactly 64 bytes SLAB_HWCACHE_ALIGN adds no padding at all, so every
 * session comes out cacheline aligned for free.
 *
 * kfree_rcu() cannot free slab-cache objects, so the callback is explicit and
 * teardown needs an rcu_barrier() before kmem_cache_destroy().
 */
static struct kmem_cache *nat_session_cache __read_mostly;

static void nat_session_free_rcu(struct rcu_head *head)
{
    kmem_cache_free(nat_session_cache,
                    container_of(head, struct nat_session, u.rcu));
}

struct xt_users_htable {
    uint32_t use;
    spinlock_t lock;
    struct hlist_head user;
};

struct user_htable_ent {
    struct rcu_head rcu;
    struct hlist_node list_node;
    uint32_t addr;
    uint16_t tcp_count;
    uint16_t udp_count;
    uint16_t other_count;
    uint8_t idle;
};

struct xt_users_htable *ht_users;

static u_int32_t nat_pool_start;
static u_int32_t nat_pool_end;

struct xt_nat_htable *ht_inner, *ht_outer;

static char *print_sockaddr(const struct sockaddr_storage *ss)
{
    static char buf[64];
    snprintf(buf, sizeof(buf), "%pISpc", ss);
    return buf;
}

static inline long timer_end(struct timespec64 start_time)
{
    struct timespec64 end_time;
    ktime_get_raw_ts64(&end_time);
    return(end_time.tv_nsec - start_time.tv_nsec);
}

static inline struct timespec64 timer_start(void)
{
    struct timespec64 start_time;
    ktime_get_raw_ts64(&start_time);
    return start_time;
}

static inline u_int32_t
get_pool_size(void)
{
    return ntohl(nat_pool_end)-ntohl(nat_pool_start)+1;
}

static inline u_int32_t
get_nat_addr(const u_int32_t addr)
{
    return htonl(ntohl(nat_pool_start)+reciprocal_scale(jhash_1word(addr, 0), get_pool_size()));
}

static inline u_int32_t
get_hash_nat_ent(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    return reciprocal_scale(jhash_3words((u32)proto, addr, (u32)port, 0), nat_hash_size);
}

static inline u_int32_t
get_hash_user_ent(const u_int32_t addr)
{
    return reciprocal_scale(jhash_1word(addr, 0), users_hash_size);
}

static int pool_table_create(void)
{
    size_t sz; /* (bytes) */
    unsigned int pool_size;
    int i;

    pool_size = get_pool_size();

    sz = sizeof(spinlock_t) * (size_t)pool_size;
    create_session_lock = kvzalloc(sz, GFP_KERNEL);

    if (create_session_lock == NULL)
        return -ENOMEM;

    for (i = 0; i < pool_size; i++) {
        spin_lock_init(&create_session_lock[i]);
    }

    printk(KERN_INFO "xt_NAT DEBUG: nat pool table mem: %zu\n", sz);

    return 0;
}

static void pool_table_remove(void)
{
    kvfree(create_session_lock);
    create_session_lock = NULL;

    printk(KERN_INFO "xt_NAT pool_table_remove DEBUG: removed\n");
}


static int users_htable_create(void)
{
    size_t sz; /* (bytes) */
    int i;

    sz = sizeof(struct xt_users_htable) * (size_t)users_hash_size;
    ht_users = kvzalloc(sz, GFP_KERNEL);

    if (ht_users == NULL)
        return -ENOMEM;

    for (i = 0; i < users_hash_size; i++) {
        spin_lock_init(&ht_users[i].lock);
        INIT_HLIST_HEAD(&ht_users[i].user);
        ht_users[i].use = 0;
    }

    printk(KERN_INFO "xt_NAT DEBUG: users htable mem: %zu\n", sz);
    return 0;
}

static void users_htable_remove(void)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    struct hlist_node *next;
    int i;

    if (ht_users == NULL)
        return;

    for (i = 0; i < users_hash_size; i++) {
        spin_lock_bh(&ht_users[i].lock);
        head = &ht_users[i].user;
        hlist_for_each_entry_safe(user, next, head, list_node) {
            hlist_del_rcu(&user->list_node);
            ht_users[i].use--;
            kfree_rcu(user, rcu);
        }

        if (ht_users[i].use != 0) {
            printk(KERN_WARNING "xt_NAT users_htable_remove ERROR: bad use value: %u in element %d\n", ht_users[i].use, i);
        }
        spin_unlock_bh(&ht_users[i].lock);
    }
    kvfree(ht_users);
    ht_users = NULL;
    printk(KERN_INFO "xt_NAT users_htable_remove DONE\n");
    return;
}

static void nat_htable_remove(void)
{
    struct nat_session *sess;
    struct hlist_node *next;
    unsigned int i, ohash;

    if (ht_inner == NULL || ht_outer == NULL) {
        kvfree(ht_inner);
        kvfree(ht_outer);
        ht_inner = NULL;
        ht_outer = NULL;
        return;
    }

    /* A session is one object in two chains, so walking ht_inner reaches all
     * of them; the outer chain is unlinked from the same place. */
    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_bh(&ht_inner[i].lock);
        hlist_for_each_entry_safe(sess, next, &ht_inner[i].session, inner_node) {
            ohash = get_hash_nat_ent(sess->proto, sess->nat_addr, sess->out_port);
            spin_lock_bh(&ht_outer[ohash].lock);
            hlist_del_rcu(&sess->outer_node);
            ht_outer[ohash].use--;
            spin_unlock_bh(&ht_outer[ohash].lock);

            hlist_del_rcu(&sess->inner_node);
            ht_inner[i].use--;
            call_rcu(&sess->u.rcu, nat_session_free_rcu);
        }
        if (ht_inner[i].use != 0)
            printk(KERN_WARNING "xt_NAT nat_htable_remove inner ERROR: bad use value: %u in element %d\n", ht_inner[i].use, i);
        spin_unlock_bh(&ht_inner[i].lock);
    }

    for (i = 0; i < nat_hash_size; i++) {
        if (ht_outer[i].use != 0)
            printk(KERN_WARNING "xt_NAT nat_htable_remove outer ERROR: bad use value: %u in element %d\n", ht_outer[i].use, i);
    }

    kvfree(ht_inner);
    kvfree(ht_outer);
    ht_inner = NULL;
    ht_outer = NULL;

    printk(KERN_INFO "xt_NAT nat_htable_remove DONE\n");
    return;
}


static int nat_htable_create(void)
{
    size_t sz; /* (bytes) */
    int i;

    sz = sizeof(struct xt_nat_htable) * (size_t)nat_hash_size;
    ht_inner = kvzalloc(sz, GFP_KERNEL);
    if (ht_inner == NULL)
        return -ENOMEM;

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_init(&ht_inner[i].lock);
        INIT_HLIST_HEAD(&ht_inner[i].session);
        ht_inner[i].use = 0;
    }

    printk(KERN_INFO "xt_NAT DEBUG: sessions htable inner mem: %zu\n", sz);

    ht_outer = kvzalloc(sz, GFP_KERNEL);
    if (ht_outer == NULL) {
        kvfree(ht_inner);
        ht_inner = NULL;
        return -ENOMEM;
    }

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_init(&ht_outer[i].lock);
        INIT_HLIST_HEAD(&ht_outer[i].session);
        ht_outer[i].use = 0;
    }

    printk(KERN_INFO "xt_NAT DEBUG: sessions htable outer mem: %zu\n", sz);
    return 0;
}

static struct nat_session *lookup_session_in(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    struct nat_session *s;
    unsigned int hash;

    hash = get_hash_nat_ent(proto, addr, port);
    hlist_for_each_entry_rcu(s, &ht_inner[hash].session, inner_node) {
        if (s->in_addr == addr && s->in_port == port && s->proto == proto && s->timeout > 0)
            return s;
    }
    return NULL;
}

static struct nat_session *lookup_session_out(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    struct nat_session *s;
    unsigned int hash;

    hash = get_hash_nat_ent(proto, addr, port);
    hlist_for_each_entry_rcu(s, &ht_outer[hash].session, outer_node) {
        if (s->nat_addr == addr && s->out_port == port && s->proto == proto && s->timeout > 0)
            return s;
    }
    return NULL;
}

static uint16_t search_free_l4_port(const uint8_t proto, const u_int32_t nataddr, const uint16_t userport)
{
    uint16_t i, freeport;
    for(i = 0; i < 64512; i++) {
        freeport = ntohs(userport) + i;

        if (freeport < 1024) {
            freeport += 1024;
        }

        if(!lookup_session_out(proto, nataddr, htons(freeport))) {
            return htons(freeport);
        }
    }
    return 0;
}

static int check_user_limits(const u_int8_t proto, const u_int32_t addr)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    unsigned int hash, is_found, ret;
    unsigned int sessions, session_limit;

    hash = get_hash_user_ent(addr);
    rcu_read_lock_bh();
    head = &ht_users[hash].user;
    is_found=0;
    /* read the tunable once: it is writable at runtime via sysfs, and the
     * counters it is compared against are uint16_t */
    session_limit = READ_ONCE(user_max_sessions);
    if (session_limit < 1)
        session_limit = 1;
    else if (session_limit > USHRT_MAX)
        session_limit = USHRT_MAX;

    hlist_for_each_entry_rcu(user, head, list_node) {
        if (user->addr == addr && user->idle < 15) {
            if (proto == IPPROTO_TCP)
                sessions = user->tcp_count;
            else if (proto == IPPROTO_UDP)
                sessions = user->udp_count;
            else
                sessions = user->other_count;
            is_found=1;
            break;
        }
    }

    ret=1;
    if (is_found==1) {
        if (sessions < session_limit) {
            ret=1;
        } else {
            ret=0;
        }
    } else {
        ret=1;
    }
    rcu_read_unlock_bh();
    return ret;
}

static void update_user_limits(const u_int8_t proto, const u_int32_t addr, const int8_t operation)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    uint16_t *count;
    unsigned int hash, is_found;
    unsigned int sz;

    hash = get_hash_user_ent(addr);
    spin_lock_bh(&ht_users[hash].lock);
    head = &ht_users[hash].user;
    is_found=0;
    hlist_for_each_entry(user, head, list_node) {
        if (user->addr == addr && user->idle < 15) {
            is_found=1;
            break;
        }
    }

    if (unlikely(is_found==0)) {
        /* There is nothing to decrement if the user entry is already gone.
         * Creating one here would apply -1 to a freshly zeroed counter and
         * wrap it to 65535, which locks the subscriber out permanently:
         * check_user_limits() then always refuses, and the cleanup timer
         * never reaps the entry because it only ages a user whose counters
         * are all zero.
         */
        if (operation < 0) {
            spin_unlock_bh(&ht_users[hash].lock);
            return;
        }

        sz = sizeof(struct user_htable_ent);
        user = kzalloc(sz, GFP_ATOMIC);

        if (user == NULL) {
            atomic64_inc(&ses_fail_nomem);
            printk_ratelimited(KERN_WARNING "xt_NAT update_user_limits ERROR: Cannot allocate memory for user_session\n");
            spin_unlock_bh(&ht_users[hash].lock);
            return;
        }

        user->addr = addr;

        hlist_add_head_rcu(&user->list_node, &ht_users[hash].user);
        ht_users[hash].use++;
        atomic64_inc(&users_active);
    }

    user->idle = 0;

    if (proto == IPPROTO_TCP) {
        count = &user->tcp_count;
    } else if (proto == IPPROTO_UDP) {
        count = &user->udp_count;
    } else {
        count = &user->other_count;
    }

    if (operation < 0) {
        if (likely(*count > 0)) {
            (*count)--;
        } else {
            printk(KERN_WARNING "xt_NAT update_user_limits ERROR: %pI4 proto %u session count underflow\n",
                   &addr, proto);
        }
    } else {
        (*count)++;
    }

    spin_unlock_bh(&ht_users[hash].lock);
    return;
}

/* socket code */
static void nat_sk_error_report(struct sock *sk)
{
    sk->sk_err = 0;
    return;
}

static struct socket *usock_open_sock(const struct sockaddr_storage *addr, void *user_data)
{
    struct socket *sock;
    int error;

    if ((error = sock_create_kern(addr->ss_family, SOCK_DGRAM, IPPROTO_UDP, &sock)) < 0) {
        printk(KERN_WARNING "xt_NAT NEL: sock_create_kern error %d\n", -error);
        return NULL;
    }
    sock->sk->sk_allocation = GFP_ATOMIC;
    sock->sk->sk_prot->unhash(sock->sk); /* hidden from input */
    sock->sk->sk_error_report = &nat_sk_error_report; /* clear ECONNREFUSED */
    sock->sk->sk_user_data = user_data; /* usock */

    if (sndbuf < SOCK_MIN_SNDBUF)
	sndbuf = SOCK_MIN_SNDBUF;

    if (sndbuf)
        sock->sk->sk_sndbuf = sndbuf;
    else
        sndbuf = sock->sk->sk_sndbuf;
    error = kernel_connect(sock, (compat_sockaddr_kern *)addr, sizeof(*addr), 0);
    if (error < 0) {
        printk(KERN_WARNING "xt_NAT NEL: error connecting UDP socket %d,"
               " don't worry, will try reconnect later.\n", -error);
        /* ENETUNREACH when no interfaces */
        sock_release(sock);
        return NULL;
    }
    return sock;
}

static void netflow_sendmsg(void *buffer, const int len)
{
    struct msghdr msg = { .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL };
    struct kvec iov = { buffer, len };
    struct netflow_sock *usock;
    int ret;

    list_for_each_entry(usock, &usock_list, list) {
        if (!usock->sock)
            usock->sock = usock_open_sock(&usock->addr, usock);

        if (!usock->sock)
            continue;

        ret = kernel_sendmsg(usock->sock, &msg, &iov, 1, (size_t)len);
        if (ret == -EINVAL) {
            if (usock->sock)
                sock_release(usock->sock);
            usock->sock = NULL;
        } else if (ret == -EAGAIN) {
            printk(KERN_WARNING "xt_NAT NEL: increase sndbuf!\n");
        }
    }
}

static void netflow_export_pdu_v9(void)
{
    struct timespec64 ts;
    int pdusize;

    if (!pdu_data_records)
        return;

    pdu.version		= htons(9);
    pdu.nr_records	= htons(pdu_data_records + 1);
    pdu.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
    ktime_get_real_ts64(&ts);
    pdu.ts_usecs	= htonl(ts.tv_sec);
    pdu.seq		= htonl(pdu_seq);
    pdu.srcID		= 0;
    pdu.template_V9	= templateV9;
    pdu.FlowSetId	= htons(flowsetID);
    pdu.FlowSetIdSize	= sizeof(struct netflow9_record) * pdu_data_records;
    pdusize = NETFLOW9_HEADER_SIZE + pdu.FlowSetIdSize;
    pdu.FlowSetIdSize	= htons(pdu.FlowSetIdSize+4);
    netflow_sendmsg(&pdu, pdusize);
    pdu_seq++;
    pdu_data_records = 0;
}

static void netflow_export_flow_v9(const uint8_t proto, const u_int32_t srcaddr, const uint16_t srcport, const u_int32_t dstaddr, const uint16_t dstport, const u_int32_t nataddr, const uint16_t natport, const int nat_event)
{
    struct netflow9_record *rec;

    spin_lock_bh(&nfsend_lock);

    rec = &pdu.flow[pdu_data_records++];

    rec->protocol	= proto;
    rec->s_port		= srcport;
    rec->s_addr		= srcaddr;
    rec->d_port		= dstport;
    rec->d_addr		= dstaddr;
    rec->n_addr		= nataddr;
    rec->n_port		= natport;
    rec->event		= nat_event;

    if (pdu_data_records == NETFLOW9_RECORDS_MAX)
        netflow_export_pdu_v9();

    spin_unlock_bh(&nfsend_lock);
}

static struct nat_session *create_nat_session(const uint8_t proto, const u_int32_t useraddr, const uint16_t userport, const u_int32_t dstaddr, const uint16_t dstport, const u_int32_t nataddr)
{
    struct nat_session *sess, *existing;
    uint16_t natport;
    unsigned int nataddr_id, hash;

    NAT_STAT_INC(tried);

    if (unlikely(check_user_limits(proto, useraddr) == 0)) {
        atomic64_inc(&ses_fail_ulimit);
        printk_ratelimited(KERN_NOTICE "xt_NAT: %pI4 exceed max allowed sessions\n", &useraddr);
        return NULL;
    }

    /* allocated before the lock: nothing here needs it, and on the paths that
     * bail out the object is simply freed - it was never published */
    sess = kmem_cache_zalloc(nat_session_cache, GFP_ATOMIC);
    if (unlikely(sess == NULL)) {
        atomic64_inc(&ses_fail_nomem);
        printk_ratelimited(KERN_WARNING "xt_NAT create_nat_session ERROR: Cannot allocate session\n");
        return NULL;
    }

    nataddr_id = ntohl(nataddr) - ntohl(nat_pool_start);
    spin_lock_bh(&create_session_lock[nataddr_id]);

    /* Contract with the caller: either NULL with no RCU read lock held, or a
     * session with rcu_read_lock_bh() held for it to drop.
     */
    rcu_read_lock_bh();
    existing = lookup_session_in(proto, useraddr, userport);
    if (unlikely(existing)) {
        spin_unlock_bh(&create_session_lock[nataddr_id]);
        kmem_cache_free(nat_session_cache, sess);
        NAT_STAT_INC(dup);
        return existing;
    }
    rcu_read_unlock_bh();

    if (likely(proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP)) {
        rcu_read_lock_bh();
        natport = search_free_l4_port(proto, nataddr, userport);
        rcu_read_unlock_bh();
        if (natport == 0) {
            atomic64_inc(&ses_fail_noport);
            printk_ratelimited(KERN_WARNING "xt_NAT create_nat_session ERROR: Not found free nat port for %d %pI4:%u -> %pI4:XXXX\n", proto, &useraddr, userport, &nataddr);
            spin_unlock_bh(&create_session_lock[nataddr_id]);
            kmem_cache_free(nat_session_cache, sess);
            return NULL;
        }
    } else {
        natport = userport;
    }

    sess->in_addr    = useraddr;
    sess->in_port    = userport;
    sess->nat_addr   = nataddr;
    sess->out_port   = natport;
    sess->u.dst.addr = dstaddr;
    sess->u.dst.port = dstport;
    sess->timeout    = 30;
    sess->proto      = proto;
    sess->flags      = 0;

    hash = get_hash_nat_ent(proto, useraddr, userport);
    spin_lock_bh(&ht_inner[hash].lock);
    hlist_add_head_rcu(&sess->inner_node, &ht_inner[hash].session);
    ht_inner[hash].use++;
    spin_unlock_bh(&ht_inner[hash].lock);

    hash = get_hash_nat_ent(proto, nataddr, natport);
    spin_lock_bh(&ht_outer[hash].lock);
    hlist_add_head_rcu(&sess->outer_node, &ht_outer[hash].session);
    ht_outer[hash].use++;
    spin_unlock_bh(&ht_outer[hash].lock);

    spin_unlock_bh(&create_session_lock[nataddr_id]);

    update_user_limits(proto, useraddr, 1);
    netflow_export_flow_v9(proto, useraddr, userport, dstaddr, dstport, nataddr, natport, 1);

    NAT_STAT_INC(created);
    NAT_STAT_INC(active);

    /* published above; the caller drops this read lock */
    rcu_read_lock_bh();
    return sess;
}

static unsigned int
nat_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    struct nat_session *session;
    uint32_t nat_addr;
    uint16_t nat_port;
    unsigned int inner_hlen;
    unsigned int icmp_off;
    const struct xt_nat_tginfo *info = par->targinfo;

    if (unlikely(skb->protocol != htons(ETH_P_IP))) {
        atomic64_inc(&pkt_drop_proto);
        return NF_DROP;
    }
    if (unlikely(ip_hdrlen(skb) != sizeof(struct iphdr))) {
        atomic64_inc(&pkt_drop_hdrlen);
        return NF_DROP;
    }

    ip = (struct iphdr *)skb_network_header(skb);

    if (unlikely(ip->frag_off & htons(IP_OFFSET))) {
        atomic64_inc(&pkt_drop_frag);
        return NF_DROP;
    }
    if (unlikely(ip->version != 4)) {
        atomic64_inc(&pkt_drop_proto);
        return NF_DROP;
    }

    if (info->variant == XTNAT_SNAT) {
        nat_addr = get_nat_addr(ip->saddr);

        if (ip->protocol == IPPROTO_TCP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct tcphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);
            skb_set_transport_header(skb, ip->ihl * 4);
            tcp = (struct tcphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            rcu_read_lock_bh();
            session = lookup_session_in(ip->protocol, ip->saddr, tcp->source);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, nat_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, nat_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, tcp->source, session->out_port, true);

                ip->saddr = nat_addr;
                tcp->source = session->out_port;

                if (tcp->fin || tcp->rst) {
                    session->timeout=10;
                    session->flags |= FLAG_TCP_FIN;
                } else if (session->flags & FLAG_TCP_FIN) {
                    session->timeout=10;
                    session->flags &= ~FLAG_TCP_FIN;
                } else if ((session->flags & FLAG_REPLIED) == 0) {
                    session->timeout=30;
                } else {
                    session->timeout=300;
                }

                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(ip->protocol, ip->saddr, tcp->source, ip->daddr, tcp->dest, nat_addr);
                if (session == NULL) {
                    atomic64_inc(&pkt_drop_nosession);
                    return NF_DROP;
                }

                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->nat_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, session->in_port, session->out_port, true);
                ip->saddr = session->nat_addr;
                tcp->source = session->out_port;
                rcu_read_unlock_bh();
            }

        } else if (ip->protocol == IPPROTO_UDP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct udphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);

            skb_set_transport_header(skb, ip->ihl * 4);
            udp = (struct udphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            rcu_read_lock_bh();
            session = lookup_session_in(ip->protocol, ip->saddr, udp->source);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, nat_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->saddr, nat_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, udp->source, session->out_port, true);
                }
                ip->saddr = nat_addr;
                udp->source = session->out_port;
                if ((session->flags & FLAG_REPLIED) == 0) {
                    session->timeout=30;
                } else {
                    session->timeout=300;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(ip->protocol, ip->saddr, udp->source, ip->daddr, udp->dest, nat_addr);
                if (session == NULL) {
                    atomic64_inc(&pkt_drop_nosession);
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->saddr, session->nat_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, session->in_port, session->out_port, true);
                }
                ip->saddr = session->nat_addr;
                udp->source = session->out_port;
                rcu_read_unlock_bh();
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct icmphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);

            skb_set_transport_header(skb, ip->ihl * 4);
            icmp = (struct icmphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            nat_port = 0;
            if (icmp->type == 0 || icmp->type == 8) {
                nat_port = icmp->un.echo.id;
            }

            rcu_read_lock_bh();
            session = lookup_session_in(ip->protocol, ip->saddr, nat_port);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, nat_addr);
                ip->saddr = nat_addr;

                if (icmp->type == 0 || icmp->type == 8) {
                    inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->out_port, true);
                    icmp->un.echo.id = session->out_port;
                }
                session->timeout=30;
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(ip->protocol, ip->saddr, nat_port, ip->daddr, nat_port, nat_addr);
                if (session == NULL) {
                    atomic64_inc(&pkt_drop_nosession);
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                ip->saddr = session->nat_addr;
                if (icmp->type == 0 || icmp->type == 8) {
                    inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->out_port, true);
                    icmp->un.echo.id = session->out_port;
                }
                rcu_read_unlock_bh();
            }
        } else {
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);

            rcu_read_lock_bh();
            session = lookup_session_in(ip->protocol, ip->saddr, 0);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, nat_addr);
                ip->saddr = nat_addr;
                if ((session->flags & FLAG_REPLIED) == 0) {
                    session->timeout=30;
                } else {
                    session->timeout=300;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(ip->protocol, ip->saddr, 0, ip->daddr, 0, nat_addr);
                if (session == NULL) {
                    atomic64_inc(&pkt_drop_nosession);
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                ip->saddr = session->nat_addr;
                rcu_read_unlock_bh();
            }
        }
    } else if (info->variant == XTNAT_DNAT) {
        if (ip->protocol == IPPROTO_TCP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(skb_headlen(skb) < ip_hdrlen(skb) + sizeof(struct tcphdr)))
                NAT_STAT_INC(frags);
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct tcphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);
            skb_set_transport_header(skb, ip->ihl * 4);
            tcp = (struct tcphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            rcu_read_lock_bh();
            session = lookup_session_out(ip->protocol, ip->daddr, tcp->dest);
            if (likely(session)) {
		skb_reset_transport_header(skb);
                csum_replace4(&ip->check, ip->daddr, session->in_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->daddr, session->in_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, tcp->dest, session->in_port, true);
                ip->daddr = session->in_addr;
                tcp->dest = session->in_port;
                if (tcp->fin || tcp->rst) {
                    session->timeout=10;
                    session->flags |= FLAG_TCP_FIN;
                } else if (session->flags & FLAG_TCP_FIN) {
                    session->timeout=10;
                    session->flags &= ~FLAG_TCP_FIN;
                } else if ((session->flags & FLAG_REPLIED) == 0) {
                    session->timeout=300;
                    session->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                NAT_STAT_INC(dnat_dropped);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(skb_headlen(skb) < ip_hdrlen(skb) + sizeof(struct udphdr)))
                NAT_STAT_INC(frags);
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct udphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);

            skb_set_transport_header(skb, ip->ihl * 4);
            udp = (struct udphdr *)skb_transport_header(skb);

            rcu_read_lock_bh();
            session = lookup_session_out(ip->protocol, ip->daddr, udp->dest);
            if (likely(session)) {
		skb_reset_transport_header(skb);
                csum_replace4(&ip->check, ip->daddr, session->in_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->daddr, session->in_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, udp->dest, session->in_port, true);
                }
                ip->daddr = session->in_addr;
                udp->dest = session->in_port;

                if ((session->flags & FLAG_REPLIED) == 0) {
                    session->timeout=300;
                    session->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                NAT_STAT_INC(dnat_dropped);
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct icmphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);

            skb_set_transport_header(skb, ip->ihl * 4);
            icmp = (struct icmphdr *)skb_transport_header(skb);

            nat_port = 0;
            if (icmp->type == 0 || icmp->type == 8) {
                nat_port = icmp->un.echo.id;
            } else if (icmp->type == 3 || icmp->type == 4 || icmp->type == 5 || icmp->type == 11 || icmp->type == 12 || icmp->type == 31) {
                NAT_STAT_INC(related_icmp);
                if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr)) {
                    atomic64_inc(&pkt_drop_trunc);
                    return NF_DROP;
                }

                if (unlikely(compat_skb_ensure_writable(skb, sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr)))) {
                    atomic64_inc(&pkt_drop_unwritable);
                    return NF_DROP;
                }

                skb_set_network_header(skb,sizeof(struct icmphdr) + sizeof(struct iphdr));
                ip = (struct iphdr *)skb_network_header(skb);
                skb_reset_network_header(skb);

                /* The quoted header carries its own length, and the transport
                 * header below is located with ip->ihl * 4 - but the length
                 * checks only ever validated sizeof(struct iphdr) of it. An
                 * ICMP error quoting a packet that carried IP options then
                 * read, and wrote, up to 40 bytes past the validated area.
                 */
                inner_hlen = ip->ihl * 4;
                if (ip->ihl < 5) {
                    atomic64_inc(&pkt_drop_hdrlen);
                    return NF_DROP;
                }

                /* All three embedded protocols below need the quoted header
                 * plus its first 8 transport bytes, and all three write into
                 * them.
                 */
                if (skb->len < sizeof(struct iphdr) + sizeof(struct icmphdr) + inner_hlen + 8) {
                    atomic64_inc(&pkt_drop_trunc);
                    return NF_DROP;
                }
                if (unlikely(compat_skb_ensure_writable(skb, sizeof(struct iphdr) + sizeof(struct icmphdr) + inner_hlen + 8))) {
                    atomic64_inc(&pkt_drop_unwritable);
                    return NF_DROP;
                }
                /* the pull above may have moved the data */
                skb_set_network_header(skb,sizeof(struct icmphdr) + sizeof(struct iphdr));
                ip = (struct iphdr *)skb_network_header(skb);
                skb_reset_network_header(skb);

                if (ip->protocol == IPPROTO_TCP) {
                    skb_set_transport_header(skb, sizeof(struct iphdr) + sizeof(struct icmphdr) + inner_hlen);
                    tcp = (struct tcphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);
                    rcu_read_lock_bh();
                    session = lookup_session_out(ip->protocol, ip->saddr, tcp->source);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->in_addr);
                        ip->saddr = session->in_addr;
                        tcp->source = session->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }

                    ip = (struct iphdr *)skb_network_header(skb);
                    csum_replace4(&ip->check, ip->daddr, session->in_addr);
                    ip->daddr = session->in_addr;
                    rcu_read_unlock_bh();
                } else if (ip->protocol == IPPROTO_UDP) {
                    skb_set_transport_header(skb, sizeof(struct iphdr) + sizeof(struct icmphdr) + inner_hlen);
                    udp = (struct udphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);
                    rcu_read_lock_bh();
                    session = lookup_session_out(ip->protocol, ip->saddr, udp->source);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->in_addr);
                        ip->saddr = session->in_addr;
                        udp->source = session->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }
                    ip = (struct iphdr *)skb_network_header(skb);

                    csum_replace4(&ip->check, ip->daddr, session->in_addr);
                    ip->daddr = session->in_addr;
                    rcu_read_unlock_bh();
                } else if (ip->protocol == IPPROTO_ICMP) {
                    skb_set_transport_header(skb, sizeof(struct iphdr) + sizeof(struct icmphdr) + inner_hlen);
                    icmp = (struct icmphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);

                    nat_port = 0;
                    if (icmp->type == 0 || icmp->type == 8) {
                        nat_port = icmp->un.echo.id;
                    }

                    rcu_read_lock_bh();
                    session = lookup_session_out(ip->protocol, ip->saddr, nat_port);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->in_addr);
                        ip->saddr = session->in_addr;

                        if (icmp->type == 0 || icmp->type == 8) {
                            inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->in_port, true);
                            icmp->un.echo.id = session->in_port;
                        }

                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }
                    ip = (struct iphdr *)skb_network_header(skb);
                    csum_replace4(&ip->check, ip->daddr, session->in_addr);
                    ip->daddr = session->in_addr;
                    rcu_read_unlock_bh();
                }

                /* The ICMP checksum covers the whole message, including the
                 * quoted header we just rewrote - addresses, ports and the
                 * quoted header's own checksum. Recompute it rather than try
                 * to fold in each of those edits separately; this is the
                 * error path, not the fast path.
                 */
                icmp_off = skb_network_offset(skb) + sizeof(struct iphdr);
                icmp = (struct icmphdr *)(skb_network_header(skb) + sizeof(struct iphdr));
                icmp->checksum = 0;
                icmp->checksum = csum_fold(skb_checksum(skb, icmp_off,
                                                        skb->len - icmp_off, 0));
                /* skb->csum described the packet as it arrived */
                if (skb->ip_summed == CHECKSUM_COMPLETE)
                    skb->ip_summed = CHECKSUM_NONE;
                return NF_ACCEPT;
            }
            rcu_read_lock_bh();
            session = lookup_session_out(ip->protocol, ip->daddr, nat_port);
            if (likely(session)) {
                csum_replace4(&ip->check, ip->daddr, session->in_addr);
                ip->daddr = session->in_addr;
                if (icmp->type == 0 || icmp->type == 8) {
                    inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->in_port, true);
                    icmp->un.echo.id = session->in_port;
                }
                if ((session->flags & FLAG_REPLIED) == 0) {
                    session->timeout=30;
                    session->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                NAT_STAT_INC(dnat_dropped);
            }
        } else {
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);

            nat_port = 0;
            rcu_read_lock_bh();
            session = lookup_session_out(ip->protocol, ip->daddr, nat_port);
            if (likely(session)) {
                csum_replace4(&ip->check, ip->daddr, session->in_addr);
                ip->daddr = session->in_addr;
                if ((session->flags & FLAG_REPLIED) == 0) {
                    session->timeout=300;
                    session->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                NAT_STAT_INC(dnat_dropped);
            }
        }
    }
    return NF_ACCEPT;
}

static void users_cleanup_timer_callback( struct timer_list *timer )
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    struct hlist_node *next;
    unsigned int i;
    u_int32_t vector_start, vector_end;

    spin_lock_bh(&users_timer_lock);

    if (ht_users == NULL) {
        printk(KERN_WARNING "xt_NAT USERS CLEAN ERROR: Found null ptr for ht_users\n");
        spin_unlock_bh(&users_timer_lock);
        return;
    }

    vector_start = users_htable_vector * (users_hash_size/60);
    if (users_htable_vector == 60) {
        vector_end = users_hash_size;
        users_htable_vector = 0;
    } else {
        vector_end = vector_start + (users_hash_size/60);
        users_htable_vector++;
    }

    for (i = vector_start; i < vector_end; i++) {
        spin_lock_bh(&ht_users[i].lock);
        if (ht_users[i].use > 0) {
            head = &ht_users[i].user;
            hlist_for_each_entry_safe(user, next, head, list_node) {
                if (user->tcp_count == 0 && user->udp_count == 0 && user->other_count == 0) {
                    user->idle++;
                }
                if (user->idle > 15) {
                    hlist_del_rcu(&user->list_node);
                    ht_users[i].use--;
                    kfree_rcu(user, rcu);
                    atomic64_dec(&users_active);
                }
            }
        }
        spin_unlock_bh(&ht_users[i].lock);
    }
    if (likely(atomic_read(&timers_state) == NAT_TIMERS_RUN))
        mod_timer( &users_cleanup_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&users_timer_lock);
}

static void sessions_cleanup_timer_callback( struct timer_list *timer )
{
    struct nat_session *sess;
    struct hlist_node *next;
    unsigned int i, ohash;
    uint8_t proto;
    u_int32_t addr;
    u_int32_t vector_start, vector_end;

    spin_lock_bh(&sessions_timer_lock);

    if (ht_inner == NULL || ht_outer == NULL) {
        printk(KERN_WARNING "xt_NAT SESSIONS CLEAN ERROR: Found null ptr for ht_inner/ht_outer\n");
        spin_unlock_bh(&sessions_timer_lock);
        return;
    }

    vector_start = nat_htable_vector * (nat_hash_size/100);
    if (nat_htable_vector == 100) {
        vector_end = nat_hash_size;
        nat_htable_vector = 0;
    } else {
        vector_end = vector_start + (nat_hash_size/100);
        nat_htable_vector++;
    }

    /* One pass over ht_inner. The session is a single object in both chains,
     * so it is unlinked from both here and freed once. The outer table no
     * longer needs a sweep of its own - and the two unlinks can no longer be
     * separated by a sweep cycle, which is what used to let a session be freed
     * while it was still reachable through the other table.
     */
    for (i = vector_start; i < vector_end; i++) {
        spin_lock_bh(&ht_inner[i].lock);
        if (ht_inner[i].use > 0) {
            hlist_for_each_entry_safe(sess, next, &ht_inner[i].session, inner_node) {
                sess->timeout -= 10;
                if (sess->timeout == 0) {
                    /* last read of u.dst: the union becomes an rcu_head below */
                    netflow_export_flow_v9(sess->proto, sess->in_addr, sess->in_port,
                                           sess->u.dst.addr, sess->u.dst.port,
                                           sess->nat_addr, sess->out_port, 2);
                } else if (sess->timeout <= -10) {
                    proto = sess->proto;
                    addr  = sess->in_addr;

                    ohash = get_hash_nat_ent(proto, sess->nat_addr, sess->out_port);
                    spin_lock_bh(&ht_outer[ohash].lock);
                    hlist_del_rcu(&sess->outer_node);
                    ht_outer[ohash].use--;
                    spin_unlock_bh(&ht_outer[ohash].lock);

                    hlist_del_rcu(&sess->inner_node);
                    ht_inner[i].use--;

                    call_rcu(&sess->u.rcu, nat_session_free_rcu);
                    NAT_STAT_DEC(active);
                    update_user_limits(proto, addr, -1);
                }
            }
        }
        spin_unlock_bh(&ht_inner[i].lock);
    }

    if (likely(atomic_read(&timers_state) == NAT_TIMERS_RUN))
        mod_timer( &sessions_cleanup_timer, jiffies + msecs_to_jiffies(100) );
    spin_unlock_bh(&sessions_timer_lock);
}

static void nf_send_timer_callback( struct timer_list *timer )
{
    spin_lock_bh(&nfsend_lock);
    netflow_export_pdu_v9();
    if (likely(atomic_read(&timers_state) == NAT_TIMERS_RUN))
        mod_timer( &nf_send_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&nfsend_lock);
}

static void nat_timers_setup(void)
{
    timer_setup( &sessions_cleanup_timer, sessions_cleanup_timer_callback, 0 );
    timer_setup( &users_cleanup_timer, users_cleanup_timer_callback, 0 );
    timer_setup( &nf_send_timer, nf_send_timer_callback, 0 );

    /* has to be RUN before the first arm, otherwise the first callback to
     * run would take itself for a teardown and never re-arm */
    atomic_set(&timers_state, NAT_TIMERS_RUN);

    mod_timer( &sessions_cleanup_timer, jiffies + msecs_to_jiffies(10 * 1000) );
    mod_timer( &users_cleanup_timer, jiffies + msecs_to_jiffies(60 * 1000) );
    mod_timer( &nf_send_timer, jiffies + msecs_to_jiffies(1000) );
}

static void nat_timers_stop(void)
{
    /* Stop the callbacks re-arming before waiting for them. atomic_xchg() is
     * a full barrier, so the new state is visible to a callback that is about
     * to decide whether to re-arm. Must not be called with any lock a
     * callback takes held: compat_del_timer_sync() waits for a running
     * callback to finish, and it may sleep.
     */
    if (atomic_xchg(&timers_state, NAT_TIMERS_STOP) == NAT_TIMERS_NONE)
        return;

    compat_del_timer_sync( &sessions_cleanup_timer );
    compat_del_timer_sync( &users_cleanup_timer );
    compat_del_timer_sync( &nf_send_timer );
}

static int nat_seq_show(struct seq_file *m, void *v)
{
    struct nat_session *session;
    struct hlist_head *head;
    unsigned int i, count;

    count=0;

    seq_printf(m, "Proto SrcIP:SrcPort -> NatIP:NatPort\n");
    for (i = 0; i < nat_hash_size; i++) {
        rcu_read_lock_bh();
        if (ht_outer[i].use > 0) {
            head = &ht_outer[i].session;
            hlist_for_each_entry_rcu(session, head, outer_node) {
                if (session->timeout > 0) {
                    seq_printf(m, "%d %pI4:%u -> %pI4:%u --- ttl: %d\n",
                               session->proto,
                               &session->in_addr, ntohs(session->in_port),
                               &session->nat_addr, ntohs(session->out_port),
                               session->timeout);
                } else {
                    seq_printf(m, "%d %pI4:%u -> %pI4:%u --- (will be removed due timeout)\n",
                               session->proto,
                               &session->in_addr, ntohs(session->in_port),
                               &session->nat_addr, ntohs(session->out_port));
                }
                count++;
            }
        }
        rcu_read_unlock_bh();
    }

    seq_printf(m, "Total translations: %d\n", count);

    return 0;
}
static int nat_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, nat_seq_show, NULL);
}
static const struct proc_ops nat_seq_fops = {
    .proc_open		= nat_seq_open,
    .proc_read		= seq_read,
    .proc_lseek		= seq_lseek,
    .proc_release	= single_release,
};


static int users_seq_show(struct seq_file *m, void *v)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    u_int32_t nataddr;
    unsigned int i, count;

    count=0;

    for (i = 0; i < users_hash_size; i++) {
        rcu_read_lock_bh();
        if (ht_users[i].use > 0) {
            head = &ht_users[i].user;
            hlist_for_each_entry_rcu(user, head, list_node) {
                if (user->idle < 15) {
                    nataddr = get_nat_addr(user->addr);
                    seq_printf(m, "%pI4 -> %pI4 (tcp: %u, udp: %u, other: %u)\n",
                               &user->addr,
                               &nataddr,
                               user->tcp_count,
                               user->udp_count,
                               user->other_count);
                    count++;
                }
            }
        }
        rcu_read_unlock_bh();
    }

    seq_printf(m, "Total users: %d\n", count);

    return 0;
}
static int users_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, users_seq_show, NULL);
}
static const struct proc_ops users_seq_fops = {
    .proc_open           = users_seq_open,
    .proc_read           = seq_read,
    .proc_lseek          = seq_lseek,
    .proc_release        = single_release,
};

static int stat_seq_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Active NAT sessions: %lld\n", NAT_STAT_READ(active));
    seq_printf(m, "Tried NAT sessions: %lld\n", NAT_STAT_READ(tried));
    seq_printf(m, "Created NAT sessions: %lld\n", NAT_STAT_READ(created));
    seq_printf(m, "Raced session creates: %lld\n", NAT_STAT_READ(dup));
    seq_printf(m, "DNAT dropped pkts: %lld\n", NAT_STAT_READ(dnat_dropped));
    seq_printf(m, "Fragmented pkts: %lld\n", NAT_STAT_READ(frags));
    seq_printf(m, "Related ICMP pkts: %lld\n", NAT_STAT_READ(related_icmp));
    seq_printf(m, "Active Users: %lld\n", atomic64_read(&users_active));
    seq_printf(m, "Max sessions per user: %d\n", READ_ONCE(user_max_sessions));

    /* why session creation refused - the first two are the capacity limits */
    seq_printf(m, "Failed sessions user limit: %lld\n", atomic64_read(&ses_fail_ulimit));
    seq_printf(m, "Failed sessions no free port: %lld\n", atomic64_read(&ses_fail_noport));
    seq_printf(m, "Failed sessions no memory: %lld\n", atomic64_read(&ses_fail_nomem));

    /* why packets were dropped */
    seq_printf(m, "Dropped no session: %lld\n", atomic64_read(&pkt_drop_nosession));
    seq_printf(m, "Dropped bad proto: %lld\n", atomic64_read(&pkt_drop_proto));
    seq_printf(m, "Dropped ip options: %lld\n", atomic64_read(&pkt_drop_hdrlen));
    seq_printf(m, "Dropped ip fragment: %lld\n", atomic64_read(&pkt_drop_frag));
    seq_printf(m, "Dropped truncated: %lld\n", atomic64_read(&pkt_drop_trunc));
    seq_printf(m, "Dropped unwritable: %lld\n", atomic64_read(&pkt_drop_unwritable));

    return 0;
}
static int stat_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, stat_seq_show, NULL);
}
static const struct proc_ops stat_seq_fops = {
    .proc_open           = stat_seq_open,
    .proc_read           = seq_read,
    .proc_lseek          = seq_lseek,
    .proc_release        = single_release,
};

#define SEPARATORS " ,;\t\n"
static int add_nf_destinations(const char *ptr)
{
    int len;

    for (; ptr; ptr += len) {
        struct sockaddr_storage ss;
        struct netflow_sock *usock;
        struct sockaddr_in *sin;
        const char *end;
        int succ = 0;

        /* skip initial separators */
        ptr += strspn(ptr, SEPARATORS);

        len = strcspn(ptr, SEPARATORS);
        if (!len)
            break;
        memset(&ss, 0, sizeof(ss));

        sin = (struct sockaddr_in *)&ss;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(2055);
        succ = in4_pton(ptr, len, (u8 *)&sin->sin_addr, -1, &end);
        if (succ && *end == ':')
            sin->sin_port = htons(simple_strtoul(++end, NULL, 0));

        if (!succ) {
            printk(KERN_ERR "xt_NAT: can't parse netflow destination: %.*s\n",
                   len, ptr);
            continue;
        }

        if (!(usock = vmalloc(sizeof(*usock)))) {
            printk(KERN_ERR "xt_NAT: can't vmalloc socket\n");
            return -ENOMEM;
        }
        memset(usock, 0, sizeof(*usock));
        usock->addr = ss;
        list_add_tail(&usock->list, &usock_list);
        printk(KERN_INFO "xt_NAT NEL: add destination %s\n", print_sockaddr(&usock->addr));
    }
    return 0;
}

static void nf_destinations_remove(void)
{
    while (!list_empty(&usock_list)) {
        struct netflow_sock *usock;

        usock = list_entry(usock_list.next, struct netflow_sock, list);
        list_del(&usock->list);
        if (usock->sock)
            sock_release(usock->sock);
        usock->sock = NULL;
        vfree(usock);
    }
}

static void nat_proc_remove(void)
{
    if (!proc_net_nat)
        return;

    remove_proc_entry( "sessions", proc_net_nat );
    remove_proc_entry( "users", proc_net_nat );
    remove_proc_entry( "statistics", proc_net_nat );
    proc_remove(proc_net_nat);
    proc_net_nat = NULL;
}

static int nat_tg_check(const struct xt_tgchk_param *par)
{
    const struct xt_nat_tginfo *info = par->targinfo;

    if (info->variant != XTNAT_SNAT && info->variant != XTNAT_DNAT) {
        printk(KERN_INFO "xt_NAT: rejecting rule with unknown variant %u\n", info->variant);
        return -EINVAL;
    }

    return 0;
}

static struct xt_target nat_tg_reg __read_mostly = {
    .name     = "NAT",
    .revision = 0,
    .family   = NFPROTO_IPV4,
    .hooks    = (1 << NF_INET_FORWARD) | (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_POST_ROUTING),
    .target   = nat_tg,
    .checkentry = nat_tg_check,
    .targetsize = sizeof(struct xt_nat_tginfo),
    .me       = THIS_MODULE,
};

static int __init nat_tg_init(void)
{
    char buff[128] = { 0 };
    int i, j, ret;

    printk(KERN_INFO "Module xt_NAT loaded\n");

    templateV9.FlowSetId	= 0;
    templateV9.Length		= htons(40);
    templateV9.TemplateId	= htons(flowsetID);
    templateV9.FieldsCount	= htons(8);
    templateV9.proto_id		= htons(4);
    templateV9.proto_len	= htons(1);
    templateV9.s_port_id	= htons(7);
    templateV9.s_port_len	= htons(2);
    templateV9.s_addr_id	= htons(8);
    templateV9.s_addr_len	= htons(4);
    templateV9.d_port_id	= htons(11);
    templateV9.d_port_len	= htons(2);
    templateV9.d_addr_id	= htons(12);
    templateV9.d_addr_len	= htons(4);
    templateV9.n_addr_id	= htons(225);
    templateV9.n_addr_len	= htons(4);
    templateV9.n_port_id	= htons(227);
    templateV9.n_port_len	= htons(2);
    templateV9.s_type_id	= htons(230);
    templateV9.s_type_len	= htons(1);

    for(i=0, j=0; i<128 && nat_pool[i] != '-' && nat_pool[i] != '\0'; i++, j++) {
        buff[j] = nat_pool[i];
    }
    nat_pool_start = in_aton(buff);

    for(i++, j=0; i<128 && nat_pool[i] != '-' && nat_pool[i] != '\0'; i++, j++) {
        buff[j] = nat_pool[i];
    }
    nat_pool_end = in_aton(buff);

    if (nat_pool_start && nat_pool_end && nat_pool_start <= nat_pool_end ) {
        printk(KERN_INFO "xt_NAT DEBUG: IP Pool from %pI4 to %pI4\n", &nat_pool_start, &nat_pool_end);
    } else {
        printk(KERN_INFO "xt_NAT DEBUG: BAD IP Pool from %pI4 to %pI4\n", &nat_pool_start, &nat_pool_end);
        return -EINVAL;
    }

    /* Both are used as the divisor in reciprocal_scale() and are sliced by
     * the GC timers (/100 and /60), so zero or negative is not merely odd -
     * kzalloc(0) hands back ZERO_SIZE_PTR, which is not NULL, so the
     * allocation check passes and the first packet dereferences it.
     */
    if (nat_hash_size < NAT_HASH_MIN || nat_hash_size > NAT_HASH_MAX) {
        printk(KERN_ERR "xt_NAT: nat_hash_size must be between %d and %d\n",
               NAT_HASH_MIN, NAT_HASH_MAX);
        return -EINVAL;
    }
    if (users_hash_size < NAT_HASH_MIN || users_hash_size > NAT_HASH_MAX) {
        printk(KERN_ERR "xt_NAT: users_hash_size must be between %d and %d\n",
               NAT_HASH_MIN, NAT_HASH_MAX);
        return -EINVAL;
    }

    if (user_max_sessions < 1 || user_max_sessions > USHRT_MAX) {
        printk(KERN_ERR "xt_NAT: user_max_sessions must be between 1 and %d\n", USHRT_MAX);
        return -EINVAL;
    }

    printk(KERN_INFO "xt_NAT DEBUG: NAT hash size: %d\n", nat_hash_size);
    printk(KERN_INFO "xt_NAT DEBUG: Users hash size: %d\n", users_hash_size);

    /* The layout is load bearing: at exactly 64 bytes the object is one
     * cacheline and SLAB_HWCACHE_ALIGN adds no padding. Adding a field would
     * silently double the cost of every lookup, so say so at build time.
     */
    BUILD_BUG_ON(sizeof(struct nat_session) != 64);

    nat_session_cache = kmem_cache_create("xt_NAT_session",
                                          sizeof(struct nat_session), 0,
                                          SLAB_HWCACHE_ALIGN, NULL);
    if (!nat_session_cache) {
        ret = -ENOMEM;
        goto err_caches;
    }

    ret = nat_htable_create();
    if (ret < 0)
        goto err_tables;

    ret = users_htable_create();
    if (ret < 0)
        goto err_tables;

    ret = pool_table_create();
    if (ret < 0)
        goto err_tables;

    ret = add_nf_destinations(nf_dest);
    if (ret < 0)
        goto err_nf_dest;

    proc_net_nat = proc_mkdir("NAT",init_net.proc_net);
    if (!proc_net_nat) {
        printk(KERN_ERR "xt_NAT ERROR: cannot create /proc/net/NAT\n");
        ret = -ENOMEM;
        goto err_nf_dest;
    }
    proc_create("sessions", 0644, proc_net_nat, &nat_seq_fops);
    proc_create("users", 0644, proc_net_nat, &users_seq_fops);
    proc_create("statistics", 0644, proc_net_nat, &stat_seq_fops);

    nat_timers_setup();

    ret = xt_register_target(&nat_tg_reg);
    if (ret < 0)
        goto err_register;

    return 0;

err_register:
    nat_timers_stop();
    nat_proc_remove();
err_nf_dest:
    nf_destinations_remove();
err_tables:
    pool_table_remove();
    users_htable_remove();
    nat_htable_remove();
err_caches:
    /* nothing has been published yet, so no RCU callbacks can be outstanding */
    kmem_cache_destroy(nat_session_cache);
    nat_session_cache = NULL;
    printk(KERN_ERR "xt_NAT ERROR: module load failed, error %d\n", ret);
    return ret;
}

static void __exit nat_tg_exit(void)
{
    xt_unregister_target(&nat_tg_reg);

    nat_timers_stop();

    nat_proc_remove();

    pool_table_remove();
    users_htable_remove();
    nat_htable_remove();

    nf_destinations_remove();

    /* the tables were torn down with call_rcu(); those callbacks must have run
     * before the caches they free into can be destroyed */
    rcu_barrier();
    kmem_cache_destroy(nat_session_cache);
    nat_session_cache = NULL;

    printk(KERN_INFO "Module xt_NAT unloaded\n");
}

module_init(nat_tg_init);
module_exit(nat_tg_exit);

MODULE_DESCRIPTION("Xtables: Full Cone NAT");
MODULE_AUTHOR("Andrei Sharaev <andr.sharaev@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_NAT");
