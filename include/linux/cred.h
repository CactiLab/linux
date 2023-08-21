/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Credentials management - see Documentation/security/credentials.rst
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_CRED_H
#define _LINUX_CRED_H

#include <linux/capability.h>
#include <linux/init.h>
#include <linux/key.h>
#include <linux/atomic.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/sched/user.h>

struct cred;
struct inode;

/*
 * COW Supplementary groups list
 */
struct group_info {
	atomic_t	usage;
	int		ngroups;
	kgid_t		gid[];
} __randomize_layout;

/**
 * get_group_info - Get a reference to a group info structure
 * @group_info: The group info to reference
 *
 * This gets a reference to a set of supplementary groups.
 *
 * If the caller is accessing a task's credentials, they must hold the RCU read
 * lock when reading.
 */
static inline struct group_info *get_group_info(struct group_info *gi)
{
	atomic_inc(&gi->usage);
	return gi;
}

/**
 * put_group_info - Release a reference to a group info structure
 * @group_info: The group info to release
 */
#define put_group_info(group_info)			\
do {							\
	if (atomic_dec_and_test(&(group_info)->usage))	\
		groups_free(group_info);		\
} while (0)

#ifdef CONFIG_MULTIUSER
extern struct group_info *groups_alloc(int);
extern void groups_free(struct group_info *);

extern int in_group_p(kgid_t);
extern int in_egroup_p(kgid_t);
extern int groups_search(const struct group_info *, kgid_t);

extern int set_current_groups(struct group_info *);
extern void set_groups(struct cred *, struct group_info *);
extern bool may_setgroups(void);
extern void groups_sort(struct group_info *);
#else
static inline void groups_free(struct group_info *group_info)
{
}

static inline int in_group_p(kgid_t grp)
{
        return 1;
}
static inline int in_egroup_p(kgid_t grp)
{
        return 1;
}
static inline int groups_search(const struct group_info *group_info, kgid_t grp)
{
	return 1;
}
#endif

/*
 * The security context of a task
 *
 * The parts of the context break down into two categories:
 *
 *  (1) The objective context of a task.  These parts are used when some other
 *	task is attempting to affect this one.
 *
 *  (2) The subjective context.  These details are used when the task is acting
 *	upon another object, be that a file, a task, a key or whatever.
 *
 * Note that some members of this structure belong to both categories - the
 * LSM security pointer for instance.
 *
 * A task has two security pointers.  task->real_cred points to the objective
 * context that defines that task's actual details.  The objective part of this
 * context is used whenever that task is acted upon.
 *
 * task->cred points to the subjective context that defines the details of how
 * that task is going to act upon another object.  This may be overridden
 * temporarily to point to another security context, but normally points to the
 * same context as task->real_cred.
 */
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct ucounts *ucounts;
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
	// GL [code] +
#ifdef CONFIG_ARM64_PTR_AUTH_CRED_PROTECT
	u_int32_t sac;				/* store the structure authentication code (SAC) of this cred structure, including tradition creds, capabilities, pointers to other structures. Not reference counters */
#endif
	//-----
} __randomize_layout;

extern void __put_cred(struct cred *);
extern void exit_creds(struct task_struct *);
extern int copy_creds(struct task_struct *, unsigned long);
extern const struct cred *get_task_cred(struct task_struct *);
extern struct cred *cred_alloc_blank(void);
extern struct cred *prepare_creds(void);
extern struct cred *prepare_exec_creds(void);
extern int commit_creds(struct cred *);
extern void abort_creds(struct cred *);
extern const struct cred *override_creds(const struct cred *);
extern void revert_creds(const struct cred *);
extern struct cred *prepare_kernel_cred(struct task_struct *);
extern int change_create_files_as(struct cred *, struct inode *);
extern int set_security_override(struct cred *, u32);
extern int set_security_override_from_ctx(struct cred *, const char *);
extern int set_create_files_as(struct cred *, struct inode *);
extern int cred_fscmp(const struct cred *, const struct cred *);
extern void __init cred_init(void);
extern int set_cred_ucounts(struct cred *);

// GL [DEBUG] +
static void my_print_cred_values_by_pointer(struct cred *cc, char *mark1) {
	if (unlikely(!cc)) {
		return;
	}
	if (unlikely((!mark1))) {
		mark1 = "";
	}
	char mark[256];
	sprintf(mark, "%s, PID=%d", mark1, current->pid);
	printk_deferred(KERN_INFO "[%s] usage at %lx, offset=%lx, value=%d", mark, (void *)&(cc->usage),(void *) &(cc->usage) - (void *) cc, atomic_read(&cc->usage));
	// printk_deferred(KERN_INFO "[%s] uid at %lx, offset=%lx, value=%d", mark, (void *)&(cc->uid),(void *) &(cc->uid) - (void *) cc, cc->uid.val);
	// printk_deferred(KERN_INFO "[%s] gid at %lx, offset=%lx, value=%d", mark, (void *)&(cc->gid),(void *) &(cc->gid) - (void *) cc, cc->gid.val);
	// printk_deferred(KERN_INFO "[%s] suid at %lx, offset=%lx, value=%d", mark, (void *)&(cc->suid),(void *) &(cc->suid) - (void *) cc, cc->suid.val);
	// printk_deferred(KERN_INFO "[%s] sgid at %lx, offset=%lx, value=%d", mark, (void *)&(cc->sgid),(void *) &(cc->sgid) - (void *) cc, cc->sgid.val);
	// printk_deferred(KERN_INFO "[%s] euid at %lx, offset=%lx, value=%d", mark, (void *)&(cc->euid),(void *) &(cc->euid) - (void *) cc, cc->euid.val);
	// printk_deferred(KERN_INFO "[%s] egid at %lx, offset=%lx, value=%d", mark, (void *)&(cc->egid),(void *) &(cc->egid) - (void *) cc, cc->egid.val);
	// printk_deferred(KERN_INFO "[%s] fsuid at %lx, offset=%lx, value=%d", mark, (void *)&(cc->fsuid),(void *) &(cc->fsuid) - (void *) cc, cc->fsuid.val);
	// printk_deferred(KERN_INFO "[%s] fsgid at %lx, offset=%lx, value=%d", mark, (void *)&(cc->fsgid),(void *) &(cc->fsgid) - (void *) cc, cc->fsgid.val);
	// printk_deferred(KERN_INFO "[%s] securebits at %lx, offset=%lx, value=%u", mark, (void *)&(cc->securebits),(void *) &(cc->securebits) - (void *) cc, cc->securebits);
	// printk_deferred(KERN_INFO "[%s] cap_inheritable at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->cap_inheritable),(void *) &(cc->cap_inheritable) - (void *) cc, cc->cap_inheritable);
	// printk_deferred(KERN_INFO "[%s] cap_permitted at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->cap_permitted),(void *) &(cc->cap_permitted) - (void *) cc, cc->cap_permitted);
	// printk_deferred(KERN_INFO "[%s] cap_effective at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->cap_effective),(void *) &(cc->cap_effective) - (void *) cc, cc->cap_effective);
	// printk_deferred(KERN_INFO "[%s] cap_bset at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->cap_bset),(void *) &(cc->cap_bset) - (void *) cc, cc->cap_bset);
	// printk_deferred(KERN_INFO "[%s] cap_ambient at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->cap_ambient),(void *) &(cc->cap_ambient) - (void *) cc, cc->cap_ambient);
// #ifdef CONFIG_KEYS
// 	printk_deferred(KERN_INFO "[%s] session_keyring at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->session_keyring),(void *) &(cc->session_keyring) - (void *) cc, cc->session_keyring);
// 	printk_deferred(KERN_INFO "[%s] process_keyring at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->process_keyring),(void *) &(cc->process_keyring) - (void *) cc, cc->process_keyring);
// 	printk_deferred(KERN_INFO "[%s] thread_keyring at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->thread_keyring),(void *) &(cc->thread_keyring) - (void *) cc, cc->thread_keyring);
// 	printk_deferred(KERN_INFO "[%s] request_key_auth at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->request_key_auth),(void *) &(cc->request_key_auth) - (void *) cc, cc->request_key_auth);
// #endif
// #ifdef CONFIG_SECURITY
// 	printk_deferred(KERN_INFO "[%s] security at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->security),(void *) &(cc->security) - (void *) cc, cc->security);
// 	printk_deferred(KERN_INFO "[%s] CURRENT (PID=%d) TASK security value=%lx", mark, current->pid, current->security);
// #endif
	// printk_deferred(KERN_INFO "[%s] user at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->user),(void *) &(cc->user) - (void *) cc, cc->user);
	// printk_deferred(KERN_INFO "[%s] user_ns at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->user_ns),(void *) &(cc->user_ns) - (void *) cc, cc->user_ns);
	// printk_deferred(KERN_INFO "[%s] ucounts at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->ucounts),(void *) &(cc->ucounts) - (void *) cc, cc->ucounts);
	// printk_deferred(KERN_INFO "[%s] group_info at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->group_info),(void *) &(cc->group_info) - (void *) cc, cc->group_info);
	// printk_deferred(KERN_INFO "[%s] group_info->usage, value=%d", mark, cc->group_info->usage);
	// printk_deferred(KERN_INFO "[%s] group_info->ngroups, value=%d", mark, cc->group_info->ngroups);
	// for(int ii = 0; ii < cc->group_info->ngroups; ++ii) {
	// 	printk_deferred(KERN_INFO "[%s] group_info->gid[%d], value=%d", mark, ii, cc->group_info->gid[ii]);
	// }
	// printk_deferred(KERN_INFO "[%s] non_rcu at %lx, offset=%lx, value=%d", mark, (void *)&(cc->non_rcu),(void *) &(cc->non_rcu) - (void *) cc, cc->non_rcu);
#ifdef CONFIG_ARM64_PTR_AUTH_CRED_PROTECT
	printk_deferred(KERN_INFO "[%s] sac at %lx, offset=%lx, value=%lx", mark, (void *)&(cc->sac),(void *) &(cc->sac) - (void *) cc, cc->sac);
#endif
}

static void my_print_cred_values_by_pointer1(struct cred *cc, char *mark1) {
	if (unlikely(!cc)) {
		return;
	}
	if (unlikely((!mark1))) {
		mark1 = "";
	}
	char mark[256];
	sprintf(mark, "%s, PID=%d", mark1, current->pid);
	uint64_t ska = 0, sko = 0, skv = 0;
	uint64_t pka = 0, pko = 0, pkv = 0;
	uint64_t tka = 0, tko = 0, tkv = 0;
	uint64_t rka = 0, rko = 0, rkv = 0;
	uint64_t sa = 0, so = 0, sv = 0;
#ifdef CONFIG_KEYS
	ska = (void *)&(cc->session_keyring);
	sko = (void *) &(cc->session_keyring) - (void *) cc;
	skv = cc->session_keyring;
	pka = (void *)&(cc->process_keyring);
	pko = (void *) &(cc->process_keyring) - (void *) cc;
	pkv = cc->process_keyring;
	tka = (void *)&(cc->thread_keyring);
	tko = (void *) &(cc->thread_keyring) - (void *) cc;
	tkv = cc->thread_keyring;
	rka = (void *)&(cc->request_key_auth);
	rko = (void *) &(cc->request_key_auth) - (void *) cc;
	rkv = cc->request_key_auth;
#endif
#ifdef CONFIG_SECURITY
	sa = (void *)&(cc->security);
	so = (void *) &(cc->security) - (void *) cc;
	sv = cc->security;
#endif
	char *s = "[%s] usage at %lx, offset=%lx, value=%d\n[%s] uid at %lx, offset=%lx, value=%d\n[%s] gid at %lx, offset=%lx, value=%d\n[%s] suid at %lx, offset=%lx, value=%d\n[%s] sgid at %lx, offset=%lx, value=%d\n[%s] euid at %lx, offset=%lx, value=%d\n[%s] egid at %lx, offset=%lx, value=%d\n[%s] fsuid at %lx, offset=%lx, value=%d\n[%s] fsgid at %lx, offset=%lx, value=%d\n[%s] securebits at %lx, offset=%lx, value=%u\n[%s] cap_inheritable at %lx, offset=%lx, value=%lx\n[%s] cap_permitted at %lx, offset=%lx, value=%lx\n[%s] cap_effective at %lx, offset=%lx, value=%lx\n[%s] cap_bset at %lx, offset=%lx, value=%lx\n[%s] cap_ambient at %lx, offset=%lx, value=%lx\n[%s] session_keyring at %lx, offset=%lx, value=%lx\n[%s] process_keyring at %lx, offset=%lx, value=%lx\n[%s] thread_keyring at %lx, offset=%lx, value=%lx\n[%s] request_key_auth at %lx, offset=%lx, value=%lx\n[%s] security at %lx, offset=%lx, value=%lx\n[%s] user at %lx, offset=%lx, value=%lx\n[%s] user_ns at %lx, offset=%lx, value=%lx\n[%s] ucounts at %lx, offset=%lx, value=%lx\n[%s] group_info at %lx, offset=%lx, value=%lx\n[%s] non_rcu at %lx, offset=%lx, value=%d";
	printk_deferred(KERN_INFO "[%s] usage at %lx, offset=%lx, value=%d\n[%s] uid at %lx, offset=%lx, value=%d\n[%s] gid at %lx, offset=%lx, value=%d\n[%s] suid at %lx, offset=%lx, value=%d\n[%s] sgid at %lx, offset=%lx, value=%d\n[%s] euid at %lx, offset=%lx, value=%d\n[%s] egid at %lx, offset=%lx, value=%d\n[%s] fsuid at %lx, offset=%lx, value=%d\n[%s] fsgid at %lx, offset=%lx, value=%d\n[%s] securebits at %lx, offset=%lx, value=%u\n[%s] cap_inheritable at %lx, offset=%lx, value=%lx\n[%s] cap_permitted at %lx, offset=%lx, value=%lx\n[%s] cap_effective at %lx, offset=%lx, value=%lx\n[%s] cap_bset at %lx, offset=%lx, value=%lx\n[%s] cap_ambient at %lx, offset=%lx, value=%lx\n[%s] session_keyring at %lx, offset=%lx, value=%lx\n[%s] process_keyring at %lx, offset=%lx, value=%lx\n[%s] thread_keyring at %lx, offset=%lx, value=%lx\n[%s] request_key_auth at %lx, offset=%lx, value=%lx\n[%s] security at %lx, offset=%lx, value=%lx\n[%s] user at %lx, offset=%lx, value=%lx\n[%s] user_ns at %lx, offset=%lx, value=%lx\n[%s] ucounts at %lx, offset=%lx, value=%lx\n[%s] group_info at %lx, offset=%lx, value=%lx\n[%s] non_rcu at %lx, offset=%lx, value=%d", mark, (void *)&(cc->usage),(void *) &(cc->usage) - (void *) cc, atomic_read(&cc->usage), mark, (void *)&(cc->uid),(void *) &(cc->uid) - (void *) cc, cc->uid.val, mark, (void *)&(cc->gid),(void *) &(cc->gid) - (void *) cc, cc->gid.val, mark, (void *)&(cc->suid),(void *) &(cc->suid) - (void *) cc, cc->suid.val, mark, (void *)&(cc->sgid),(void *) &(cc->sgid) - (void *) cc, cc->sgid.val, mark, (void *)&(cc->euid),(void *) &(cc->euid) - (void *) cc, cc->euid.val, mark, (void *)&(cc->egid),(void *) &(cc->egid) - (void *) cc, cc->egid.val, mark, (void *)&(cc->fsuid),(void *) &(cc->fsuid) - (void *) cc, cc->fsuid.val, mark, (void *)&(cc->fsgid),(void *) &(cc->fsgid) - (void *) cc, cc->fsgid.val, mark, (void *)&(cc->securebits),(void *) &(cc->securebits) - (void *) cc, cc->securebits, mark, (void *)&(cc->cap_inheritable),(void *) &(cc->cap_inheritable) - (void *) cc, cc->cap_inheritable, mark, (void *)&(cc->cap_permitted),(void *) &(cc->cap_permitted) - (void *) cc, cc->cap_permitted, mark, (void *)&(cc->cap_effective),(void *) &(cc->cap_effective) - (void *) cc, cc->cap_effective, mark, (void *)&(cc->cap_bset),(void *) &(cc->cap_bset) - (void *) cc, cc->cap_bset, mark, (void *)&(cc->cap_ambient),(void *) &(cc->cap_ambient) - (void *) cc, cc->cap_ambient, mark, ska, sko, skv, mark, pka, pko, pkv, mark, tka, tko, tkv, mark, rka, rko, rkv, mark, sa, so, sv, mark, (void *)&(cc->user),(void *) &(cc->user) - (void *) cc, cc->user, mark, (void *)&(cc->user_ns),(void *) &(cc->user_ns) - (void *) cc, cc->user_ns, mark, (void *)&(cc->ucounts),(void *) &(cc->ucounts) - (void *) cc, cc->ucounts, mark, (void *)&(cc->group_info),(void *) &(cc->group_info) - (void *) cc, cc->group_info, mark, (void *)&(cc->non_rcu),(void *) &(cc->non_rcu) - (void *) cc, cc->non_rcu);
}

static void my_print_cred_values(char *mark) {
	printk_deferred(KERN_INFO "=====Cred=====%s", mark);
	if (likely(current)) {
		printk_deferred(KERN_INFO "current at %lx, PID=%d, PPID=%d CMD=%s\n", current, current->pid, current->real_parent->pid, current->comm);
		if (likely(current->cred)) {
			printk_deferred(KERN_INFO "cred at %lx", current->cred);
			printk_deferred(KERN_INFO "ptracer_cred at %lx", current->ptracer_cred);
			printk_deferred(KERN_INFO "real_cred at %lx", current->real_cred);
			struct cred *cc = current->cred;
			my_print_cred_values_by_pointer(cc, mark);
		}
	} else {
		printk(KERN_INFO "Warning: `current` is NULL");
	}
	printk(KERN_INFO "----------------");
}

static void my_print_cred_values1(char *mark1) {
	if (unlikely(!current)) {
		printk(KERN_INFO "Warning: `current` is NULL");
		return;
	}
	if (unlikely((!mark1))) {
		mark1 = "";
	}
	char mark[256];
	sprintf(mark, "%s, PID=%d", mark1, current->pid);
	struct cred *cc = current->cred;
	uint64_t ska = 0, sko = 0, skv = 0;
	uint64_t pka = 0, pko = 0, pkv = 0;
	uint64_t tka = 0, tko = 0, tkv = 0;
	uint64_t rka = 0, rko = 0, rkv = 0;
	uint64_t sa = 0, so = 0, sv = 0;
#ifdef CONFIG_KEYS
	ska = (void *)&(cc->session_keyring);
	sko = (void *) &(cc->session_keyring) - (void *) cc;
	skv = cc->session_keyring;
	pka = (void *)&(cc->process_keyring);
	pko = (void *) &(cc->process_keyring) - (void *) cc;
	pkv = cc->process_keyring;
	tka = (void *)&(cc->thread_keyring);
	tko = (void *) &(cc->thread_keyring) - (void *) cc;
	tkv = cc->thread_keyring;
	rka = (void *)&(cc->request_key_auth);
	rko = (void *) &(cc->request_key_auth) - (void *) cc;
	rkv = cc->request_key_auth;
#endif
#ifdef CONFIG_SECURITY
	sa = (void *)&(cc->security);
	so = (void *) &(cc->security) - (void *) cc;
	sv = cc->security;
#endif
	printk_deferred(KERN_INFO "=====Cred=====%s\ncurrent at %lx, PID=%d, PPID=%d CMD=%s\ncred at %lx\nptracer_cred at %lx\nreal_cred at %lx\n[%s] usage at %lx, offset=%lx, value=%d\n[%s] uid at %lx, offset=%lx, value=%d\n[%s] gid at %lx, offset=%lx, value=%d\n[%s] suid at %lx, offset=%lx, value=%d\n[%s] sgid at %lx, offset=%lx, value=%d\n[%s] euid at %lx, offset=%lx, value=%d\n[%s] egid at %lx, offset=%lx, value=%d\n[%s] fsuid at %lx, offset=%lx, value=%d\n[%s] fsgid at %lx, offset=%lx, value=%d\n[%s] securebits at %lx, offset=%lx, value=%u\n[%s] cap_inheritable at %lx, offset=%lx, value=%lx\n[%s] cap_permitted at %lx, offset=%lx, value=%lx\n[%s] cap_effective at %lx, offset=%lx, value=%lx\n[%s] cap_bset at %lx, offset=%lx, value=%lx\n[%s] cap_ambient at %lx, offset=%lx, value=%lx\n[%s] session_keyring at %lx, offset=%lx, value=%lx\n[%s] process_keyring at %lx, offset=%lx, value=%lx\n[%s] thread_keyring at %lx, offset=%lx, value=%lx\n[%s] request_key_auth at %lx, offset=%lx, value=%lx\n[%s] security at %lx, offset=%lx, value=%lx\n[%s] user at %lx, offset=%lx, value=%lx\n[%s] user_ns at %lx, offset=%lx, value=%lx\n[%s] ucounts at %lx, offset=%lx, value=%lx\n[%s] group_info at %lx, offset=%lx, value=%lx\n[%s] non_rcu at %lx, offset=%lx, value=%d\n----------------", mark, current, current->pid, current->real_parent->pid, current->comm, current->cred, current->ptracer_cred, current->real_cred, mark, (void *)&(cc->usage),(void *) &(cc->usage) - (void *) cc, atomic_read(&cc->usage), mark, (void *)&(cc->uid),(void *) &(cc->uid) - (void *) cc, cc->uid.val, mark, (void *)&(cc->gid),(void *) &(cc->gid) - (void *) cc, cc->gid.val, mark, (void *)&(cc->suid),(void *) &(cc->suid) - (void *) cc, cc->suid.val, mark, (void *)&(cc->sgid),(void *) &(cc->sgid) - (void *) cc, cc->sgid.val, mark, (void *)&(cc->euid),(void *) &(cc->euid) - (void *) cc, cc->euid.val, mark, (void *)&(cc->egid),(void *) &(cc->egid) - (void *) cc, cc->egid.val, mark, (void *)&(cc->fsuid),(void *) &(cc->fsuid) - (void *) cc, cc->fsuid.val, mark, (void *)&(cc->fsgid),(void *) &(cc->fsgid) - (void *) cc, cc->fsgid.val, mark, (void *)&(cc->securebits),(void *) &(cc->securebits) - (void *) cc, cc->securebits, mark, (void *)&(cc->cap_inheritable),(void *) &(cc->cap_inheritable) - (void *) cc, cc->cap_inheritable, mark, (void *)&(cc->cap_permitted),(void *) &(cc->cap_permitted) - (void *) cc, cc->cap_permitted, mark, (void *)&(cc->cap_effective),(void *) &(cc->cap_effective) - (void *) cc, cc->cap_effective, mark, (void *)&(cc->cap_bset),(void *) &(cc->cap_bset) - (void *) cc, cc->cap_bset, mark, (void *)&(cc->cap_ambient),(void *) &(cc->cap_ambient) - (void *) cc, cc->cap_ambient, mark, ska, sko, skv, mark, pka, pko, pkv, mark, tka, tko, tkv, mark, rka, rko, rkv, mark, sa, so, sv, mark, (void *)&(cc->user),(void *) &(cc->user) - (void *) cc, cc->user, mark, (void *)&(cc->user_ns),(void *) &(cc->user_ns) - (void *) cc, cc->user_ns, mark, (void *)&(cc->ucounts),(void *) &(cc->ucounts) - (void *) cc, cc->ucounts, mark, (void *)&(cc->group_info),(void *) &(cc->group_info) - (void *) cc, cc->group_info, mark, (void *)&(cc->non_rcu),(void *) &(cc->non_rcu) - (void *) cc, cc->non_rcu);
}

static void my_print_cred_values_simplified(char *mark) {
	printk_deferred(KERN_INFO "=====Simplified Cred=====%s\ncurrent at %lx, PID=%d, PPID=%d CMD=%s\ncred at %lx\nptracer_cred at %lx\nreal_cred at %lx\n[%s] usage at %lx, offset=%lx, value=%d\n[%s] uid at %lx, offset=%lx, value=%d\n[%s] euid at %lx, offset=%lx, value=%d\n-----------------\n", mark, current, current->pid, current->real_parent->pid, current->comm, current->cred, current->ptracer_cred, current->real_cred, mark, (void *)&(current->cred->usage),(void *) &(current->cred->usage) - (void *) current->cred, atomic_read(&current->cred->usage), mark, (void *)&(current->cred->uid),(void *) &(current->cred->uid) - (void *) current->cred, current->cred->uid.val, mark, (void *)&(current->cred->euid),(void *) &(current->cred->euid) - (void *) current->cred, current->cred->euid.val);

}
//-----


// GL [code] +
#ifdef CONFIG_ARM64_PTR_AUTH_CRED_PROTECT
/**
 * get_cred_field_pac - Calculate pointer authentication code using ARMv8.3a PACGA instruction
 * 
 * @field_pointer The pointer to the input data
 * @field_size The size of the data in byte, greater than 0
 * @xm The initial value for context of PACGA instruction
 * 
 * This function is only for get_cred_sac, don't call it anywhere else.
 * 
 * Let the token "xn" be the input data for PACGA, xn is 64 bits.
 * If field_size is 8, the data is 64 bits, perfect for PACGA.
 * If field_size is less than 8, pad 0 for the most significant bits of xn.
 * If field_size is greater than 8, use PACGA multiple times, 8 bytes by 8 bytees.
 * In this case, the initial context is xm, the context for the next PACGA would be 
 * the result of the previous PACGA instruction.
 * 
 * Return pointer authentication code in 64 bits. The higher 32 bits are the PAC,
 * the lower 32 bits will always be 0. This is the raw data calculated by PACGA.
*/
static inline __attribute__((always_inline)) u_int64_t get_cred_field_pac(const void *field_pointer, size_t field_size, u_int64_t xm) {
	if (field_size <= 0) {
		return 0;
	}

	/* For copying data byte by byte */
	char *field = (char *) field_pointer;
	/* Loop control variable */
	size_t total_chunk_size = 0;
	/* Final result */
	u_int64_t xd;
	/* Input data for PACGA */
	u_int64_t xn;
	/* Temporary variable */
	u_int64_t t;

	/* The number of loop is ceil(field_size / 8) */
	while (total_chunk_size < field_size) {
		size_t current_chunk_size = (field_size - total_chunk_size >= 8) ? 8 : field_size - total_chunk_size;
		xn = 0L;

		/* copy data to the variable xn */
		int i = 0;
		for (; i < current_chunk_size; ++i) {
			t = (u_int64_t) (*(field + i));
			xn |= t << (8 * i);
		}

		/* PACGA instruction is for ARMv8.3a
		 * variable xn and xm will be the input operators for PACGA
		 * variable xd takes the result
		 */
		asm volatile(
			"PACGA %[out], %[val], %[context]\n\t"
			: [out] "=r" (xd)
			: [val] "r" (xn), [context] "r" (xm)
			:
		);
		// printk(KERN_INFO "---------------------\n");
		// printk(KERN_INFO "xn = %lx, xm = %lx, xd = %lx\n", xn, xm, xd);
		// printk(KERN_INFO "---------------------\n");
		total_chunk_size += 8;
		field += 8;
		xm = xd;
	}
	return xd;
}

/**
 * get_cred_sac - Calculate structure authentication code (SAC) for struct cred
 * 
 * @cred The pointer to the cred structure, it won't be changed
 * 
 * Only some fields of struct cred will be used for calculating SAC.
 * The initial value of context of PACGA is the address of cred.
 * The previous result of PACGA will be the context for the next PACGA.
 * 
 * Return the 32 bits of SAC
*/
static inline __attribute__((always_inline)) u_int32_t get_cred_sac(const struct cred *cred) {
	
	u_int64_t xm = (u_int64_t) cred;
	xm = get_cred_field_pac(&cred->uid.val, sizeof(cred->uid.val), xm);
	xm = get_cred_field_pac(&cred->gid.val, sizeof(cred->gid.val), xm);
	xm = get_cred_field_pac(&cred->suid.val, sizeof(cred->suid.val), xm);
	xm = get_cred_field_pac(&cred->sgid.val, sizeof(cred->sgid.val), xm);
	xm = get_cred_field_pac(&cred->euid.val, sizeof(cred->euid.val), xm);
	xm = get_cred_field_pac(&cred->egid.val, sizeof(cred->egid.val), xm);
	xm = get_cred_field_pac(&cred->fsuid.val, sizeof(cred->fsuid.val), xm);
	xm = get_cred_field_pac(&cred->fsgid.val, sizeof(cred->fsgid.val), xm);
	xm = get_cred_field_pac(&cred->securebits, sizeof(cred->securebits), xm);
	xm = get_cred_field_pac(&cred->cap_inheritable.val, sizeof(cred->cap_inheritable.val), xm);
	xm = get_cred_field_pac(&cred->cap_permitted.val, sizeof(cred->cap_permitted.val), xm);
	xm = get_cred_field_pac(&cred->cap_effective.val, sizeof(cred->cap_effective.val), xm);
	xm = get_cred_field_pac(&cred->cap_bset.val, sizeof(cred->cap_bset.val), xm);
	xm = get_cred_field_pac(&cred->cap_ambient.val, sizeof(cred->cap_ambient.val), xm);
	xm = get_cred_field_pac(&cred->user, sizeof(cred->user), xm);
	xm = get_cred_field_pac(&cred->user_ns, sizeof(cred->user_ns), xm);
	xm = get_cred_field_pac(&cred->ucounts, sizeof(cred->ucounts), xm);
	xm = get_cred_field_pac(&cred->group_info, sizeof(cred->group_info), xm);
	xm = get_cred_field_pac(&cred->rcu, sizeof(cred->rcu), xm);
	
	return xm >> 32;
}

/**
 * sac_sign_cred - Sign a cred structure
 * 
 * @cred is the point to the credential structure
 * 
 * Nothing will return, but the "sac" filed in cred will be changd
*/
static inline __attribute__((always_inline)) void sac_sign_cred(struct cred *cred, char *info) {
	u_int32_t sac = get_cred_sac(cred);
	cred -> sac = sac;
	printk_deferred(KERN_INFO "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS");
	printk_deferred(KERN_INFO "[%s] cred is at %lx, pid=%d, correct sac=%x", info, cred, current->pid, sac);
	my_print_cred_values_by_pointer(cred, "Sign");
	printk_deferred(KERN_INFO "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS");
}

/**
 * sac_validate_cred - Validate the SAC of a cred structure
 * 
 * @cred is the point to the credential structure, it won't be changed
 * 
 * Calculate the SAC again.
 * 
 * Return the address of cred if matched; kerenl panic will be triggered if not mathced
*/
static inline __attribute__((always_inline)) struct cred * sac_validate_cred(const struct cred *cred, char *info) {
	u_int32_t sac = get_cred_sac(cred);
	if (cred -> sac == sac) {
		printk_deferred(KERN_INFO "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV");
		printk_deferred(KERN_INFO "[%s] cred is at %lx, pid=%d, correct sac=%x", info, cred, current->pid, sac);
		printk_deferred(KERN_INFO "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV");
			return cred;
	}
	// panic("Cred struct (%p) integirty check failed\n", cred);
	printk_deferred(KERN_INFO "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	printk_deferred(KERN_INFO "[%s] cred is at %lx, pid=%d, correct sac=%x", info, cred, current->pid, sac);
	my_print_cred_values_by_pointer(cred, "Validation Error");
	printk_deferred(KERN_INFO "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	// panic("[%s] Cred struct (%p) integirty check failed\n", info, cred);
	return cred;
}

static inline __attribute__((always_inline)) struct cred * sac_validate_cred1(const struct cred *cred, char *info) {
	u_int32_t sac = get_cred_sac(cred);
	if (cred -> sac == sac)
		return cred;
	panic("[%s] Cred struct (%p) integirty check failed\n", info, cred);
}
#else
static void sac_sign_cred(struct cred *) {

}

static struct cred * sac_validate_cred(const struct cred *c, char *info) {
	return c;
}

static struct cred * sac_validate_cred1(const struct cred *c, char *info) {
	return c;
}

#endif
//-----

/*
 * check for validity of credentials
 */
#ifdef CONFIG_DEBUG_CREDENTIALS
extern void __noreturn __invalid_creds(const struct cred *, const char *, unsigned);
extern void __validate_process_creds(struct task_struct *,
				     const char *, unsigned);

extern bool creds_are_invalid(const struct cred *cred);

static inline void __validate_creds(const struct cred *cred,
				    const char *file, unsigned line)
{
	if (unlikely(creds_are_invalid(cred)))
		__invalid_creds(cred, file, line);
}

#define validate_creds(cred)				\
do {							\
	__validate_creds((cred), __FILE__, __LINE__);	\
} while(0)

#define validate_process_creds()				\
do {								\
	__validate_process_creds(current, __FILE__, __LINE__);	\
} while(0)

extern void validate_creds_for_do_exit(struct task_struct *);
#else
static inline void validate_creds(const struct cred *cred)
{
}
static inline void validate_creds_for_do_exit(struct task_struct *tsk)
{
}
static inline void validate_process_creds(void)
{
}
#endif

static inline bool cap_ambient_invariant_ok(const struct cred *cred)
{
	return cap_issubset(cred->cap_ambient,
			    cap_intersect(cred->cap_permitted,
					  cred->cap_inheritable));
}

/**
 * get_new_cred - Get a reference on a new set of credentials
 * @cred: The new credentials to reference
 *
 * Get a reference on the specified set of new credentials.  The caller must
 * release the reference.
 */
static inline struct cred *get_new_cred(struct cred *cred)
{
	atomic_inc(&cred->usage);
	return cred;
}

/**
 * get_cred - Get a reference on a set of credentials
 * @cred: The credentials to reference
 *
 * Get a reference on the specified set of credentials.  The caller must
 * release the reference.  If %NULL is passed, it is returned with no action.
 *
 * This is used to deal with a committed set of credentials.  Although the
 * pointer is const, this will temporarily discard the const and increment the
 * usage count.  The purpose of this is to attempt to catch at compile time the
 * accidental alteration of a set of credentials that should be considered
 * immutable.
 */
// GL don't validate here, error happens at copy_process
static inline const struct cred *get_cred(const struct cred *cred)
{
	printk(KERN_INFO "get_cred current at %lx, PID=%d, PPID=%d CMD=%s\n", current, current->pid, current->real_parent->pid, current->comm);
	struct cred *nonconst_cred = (struct cred *) cred;
	if (!cred)
		return cred;
	validate_creds(cred);
	nonconst_cred->non_rcu = 0;
	return get_new_cred(nonconst_cred);
}

static inline const struct cred *get_cred_rcu(const struct cred *cred)
{
	struct cred *nonconst_cred = (struct cred *) cred;
	if (!cred)
		return NULL;
	if (!atomic_inc_not_zero(&nonconst_cred->usage))
		return NULL;
	validate_creds(cred);
	nonconst_cred->non_rcu = 0;
	return cred;
}

/**
 * put_cred - Release a reference to a set of credentials
 * @cred: The credentials to release
 *
 * Release a reference to a set of credentials, deleting them when the last ref
 * is released.  If %NULL is passed, nothing is done.
 *
 * This takes a const pointer to a set of credentials because the credentials
 * on task_struct are attached by const pointers to prevent accidental
 * alteration of otherwise immutable credential sets.
 */
static inline void put_cred(const struct cred *_cred)
{
	struct cred *cred = (struct cred *) _cred;

	if (cred) {
		validate_creds(cred);
		if (atomic_dec_and_test(&(cred)->usage))
			__put_cred(cred);
	}
}

/**
 * current_cred - Access the current task's subjective credentials
 *
 * Access the subjective credentials of the current task.  RCU-safe,
 * since nobody else can modify it.
 */
// GL can we sign here????????????????
// GL [code] modify
#define current_cred() \
	sac_validate_cred1(rcu_dereference_protected(current->cred, 1), "current_cred")
//-----

/**
 * current_real_cred - Access the current task's objective credentials
 *
 * Access the objective credentials of the current task.  RCU-safe,
 * since nobody else can modify it.
 */
#define current_real_cred() \
	rcu_dereference_protected(current->real_cred, 1)

/**
 * __task_cred - Access a task's objective credentials
 * @task: The task to query
 *
 * Access the objective credentials of a task.  The caller must hold the RCU
 * readlock.
 *
 * The result of this function should not be passed directly to get_cred();
 * rather get_task_cred() should be used instead.
 */
#define __task_cred(task)	\
	rcu_dereference((task)->real_cred)

/**
 * get_current_cred - Get the current task's subjective credentials
 *
 * Get the subjective credentials of the current task, pinning them so that
 * they can't go away.  Accessing the current task's credentials directly is
 * not permitted.
 */
#define get_current_cred()				\
	get_cred(current_cred())

/**
 * get_current_user - Get the current task's user_struct
 *
 * Get the user record of the current task, pinning it so that it can't go
 * away.
 */
#define get_current_user()				\
({							\
	struct user_struct *__u;			\
	const struct cred *__cred;			\
	__cred = current_cred();			\
	__u = get_uid(__cred->user);			\
	__u;						\
})

/**
 * get_current_groups - Get the current task's supplementary group list
 *
 * Get the supplementary group list of the current task, pinning it so that it
 * can't go away.
 */
#define get_current_groups()				\
({							\
	struct group_info *__groups;			\
	const struct cred *__cred;			\
	__cred = current_cred();			\
	__groups = get_group_info(__cred->group_info);	\
	__groups;					\
})

// GL probably we don't want to validate here or other similar functions,
// GL this macro will be called in copy_cred when the new cred structure hasn't been committed
#define task_cred_xxx(task, xxx)			\
({							\
	__typeof__(((struct cred *)NULL)->xxx) ___val;	\
	rcu_read_lock();				\
	___val = __task_cred((task))->xxx;		\
	rcu_read_unlock();				\
	___val;						\
})

#define task_uid(task)		(task_cred_xxx((task), uid))
#define task_euid(task)		(task_cred_xxx((task), euid))
#define task_ucounts(task)	(task_cred_xxx((task), ucounts))

#define current_cred_xxx(xxx)			\
({						\
	current_cred()->xxx;			\
})

#define current_uid()		(current_cred_xxx(uid))
#define current_gid()		(current_cred_xxx(gid))
#define current_euid()		(current_cred_xxx(euid))
#define current_egid()		(current_cred_xxx(egid))
#define current_suid()		(current_cred_xxx(suid))
#define current_sgid()		(current_cred_xxx(sgid))
#define current_fsuid() 	(current_cred_xxx(fsuid))
#define current_fsgid() 	(current_cred_xxx(fsgid))
#define current_cap()		(current_cred_xxx(cap_effective))
#define current_user()		(current_cred_xxx(user))
#define current_ucounts()	(current_cred_xxx(ucounts))

extern struct user_namespace init_user_ns;
#ifdef CONFIG_USER_NS
#define current_user_ns()	(current_cred_xxx(user_ns))
#else
static inline struct user_namespace *current_user_ns(void)
{
	return &init_user_ns;
}
#endif


#define current_uid_gid(_uid, _gid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_uid) = __cred->uid;			\
	*(_gid) = __cred->gid;			\
} while(0)

#define current_euid_egid(_euid, _egid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_euid) = __cred->euid;		\
	*(_egid) = __cred->egid;		\
} while(0)

#define current_fsuid_fsgid(_fsuid, _fsgid)	\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_fsuid) = __cred->fsuid;		\
	*(_fsgid) = __cred->fsgid;		\
} while(0)

#endif /* _LINUX_CRED_H */
