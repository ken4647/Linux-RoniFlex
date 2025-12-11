/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_RBNX_H
#define _LINUX_SCHED_RBNX_H

#include <linux/sched.h>

#define MAGIC_RBNX_PRIO   256

static inline int rbnx_prio(int prio)
{
	if (unlikely(prio == MAGIC_RBNX_PRIO))
		return 1;
	return 0;
}

static inline int rbnx_task(struct task_struct *p)
{
	return rbnx_prio(p->prio);
}


#endif /* _LINUX_SCHED_RBNX_H */
