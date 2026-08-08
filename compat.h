/* This code is derived from the Linux Kernel sources intended
 * to maintain compatibility with different Kernel versions.
 * Copyright of original source is of respective Linux Kernel authors.
 * License is GPLv2.
 */

#ifndef COMPAT_CGNAT_H
#define COMPAT_CGNAT_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
# define sock_create_kern(f, t, p, s) sock_create_kern(&init_net, f, t, p, s)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,16,0)
# define compat_del_timer_sync(t) timer_delete_sync(t)
# define compat_del_timer(t) timer_delete(t)
#else
# define compat_del_timer_sync(t) del_timer_sync(t)
# define compat_del_timer(t) del_timer(t)
#endif

/* ---- 6.19 deprecated struct sockaddr for in-kernel callbacks and replaced it
 *      with struct sockaddr_unsized, a flexible-array variant, in proto_ops
 *      and in kernel_connect(). 6.18 and earlier still take struct sockaddr.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,19,0)
# define compat_sockaddr_kern struct sockaddr_unsized
#else
# define compat_sockaddr_kern struct sockaddr
#endif

/* skb_make_writable() was replaced by skb_ensure_writable() in 5.2
 * (36976d70b426 "net: remove skb_make_writable"). The old one returns
 * true on success, the new one 0.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
# define compat_skb_ensure_writable(s, l) skb_ensure_writable(s, l)
#else
# define compat_skb_ensure_writable(s, l) (skb_make_writable(s, l) ? 0 : -ENOMEM)
#endif

#endif /* COMPAT_CGNAT_H */
