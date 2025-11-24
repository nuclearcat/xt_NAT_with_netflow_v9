/* This code is derived from the Linux Kernel sources intended
 * to maintain compatibility with different Kernel versions.
 * Copyright of original source is of respective Linux Kernel authors.
 * License is GPLv2.
 */

#ifndef COMPAT_NAT_H
#define COMPAT_NAT_H

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

#endif /* COMPAT_NAT_H */
