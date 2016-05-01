#ifndef __KERNEL_INC_H__
#define __KERNEL_INC_H__

typedef struct {
	int counter;
} atomic_t;

#define _LINUX_CAPABILITY_U32S_3     2
#define _KERNEL_CAPABILITY_U32S    _LINUX_CAPABILITY_U32S_3

typedef struct kernel_cap_struct {
	uint32_t cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;

struct cred {
	atomic_t	usage;
	uid_t		uid;		/* real UID of the task */
	gid_t		gid;		/* real GID of the task */
	uid_t		suid;		/* saved UID of the task */
	gid_t		sgid;		/* saved GID of the task */
	uid_t		euid;		/* effective UID of the task */
	gid_t		egid;		/* effective GID of the task */
	uid_t		fsuid;		/* UID for VFS ops */
	gid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
};

#endif
