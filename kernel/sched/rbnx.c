// SPDX-License-Identifier: GPL-2.0
/*
 * Robonix Scheduling Class (mapped to the SCHED_FIFO and SCHED_RR
 * policies)
 */
#include "sched.h"

#include <linux/atomic.h>
#include <linux/cpumask.h>

/*
 * Debug: set to 1 to enable trace prints in hot paths (use printk_ratelimited).
 * Or enable at runtime: echo 1 > /sys/kernel/debug/rbnx_debug (if debugfs entry added).
 */
#define RBNX_DEBUG 1
#ifndef RBNX_DEBUG
#define RBNX_DEBUG 0
#endif
#define rbnx_dbg(fmt, ...) \
	do { if (RBNX_DEBUG) printk_ratelimited(KERN_DEBUG "rbnx: " fmt, ##__VA_ARGS__); } while (0)

static inline struct task_struct *rbnx_task_of(struct sched_rbnx_entity *rbnx_se)
{
	return container_of(rbnx_se, struct task_struct, rbnx);
}

static inline struct rq *rq_of_rbnx_rq(struct rbnx_rq *rbnx_rq)
{
	return container_of(rbnx_rq, struct rq, rbnx);
}

static inline u64 sched_rbnx_runtime(struct rbnx_rq *rbnx_rq)
{
	return rbnx_rq->rbnx_runtime;
}

static inline struct rq *rq_of_rbnx_se(struct sched_rbnx_entity *rbnx_se)
{
	struct task_struct *p;
    p = rbnx_task_of(rbnx_se);

	return task_rq(p);
}

static inline struct rbnx_rq *rbnx_rq_of_se(struct sched_rbnx_entity *rbnx_se)
{
	struct rq *rq;
    rq = rq_of_rbnx_se(rbnx_se);

	return &rq->rbnx;
}

static inline int on_rbnx_rq(struct sched_rbnx_entity *rbnx_se)
{
	return rbnx_se->on_rq;
}

inline void insert_rbnx_se(struct rbnx_rq* rbnx_rq, struct sched_rbnx_entity * rbnx_se){
	rbnx_rq->queue[rbnx_rq->num] = rbnx_se;
	rbnx_rq->num++;
	rbnx_se->on_rq = 1;
}

inline void remove_rbnx_se(struct rbnx_rq* rbnx_rq, struct sched_rbnx_entity * rbnx_se){
	int i;
	if(rbnx_rq->num<=0){
		return;
	}
	for(i=0;i<rbnx_rq->num;i++){
		if(rbnx_rq->queue[i]==rbnx_se){
			break;
		}
	}
	rbnx_rq->num--;
	for(;i<rbnx_rq->num;i++){
		rbnx_rq->queue[i]=rbnx_rq->queue[i+1];
	}
	rbnx_se->on_rq = 0;
}

inline struct sched_rbnx_entity * find_task_rbnx_se(struct rbnx_rq* rbnx_rq, struct task_struct* task){
	int i;
    struct sched_rbnx_entity* nse;
    struct task_struct* ntask;
	if(rbnx_rq->num<=0){
		return NULL;
	}
	for(i=0;i<rbnx_rq->num;i++){
		nse = rbnx_rq->queue[i];
		ntask = rbnx_task_of(nse);
		if(ntask==task){
			return nse;
		}
	}

	return NULL;
}

// [Important]: 
// choose the sched_rbnx_entity with the oldest vlast
inline struct sched_rbnx_entity* get_oldest_vlast_se(struct rbnx_rq* rbnx_rq){
	int i;
    struct sched_rbnx_entity* nse;
	struct sched_rbnx_entity* ret_se;
	unsigned long long oldest_vlast;
    unsigned long long vlast;

	unsigned long long times;
	unsigned long long min_times;

    ret_se=NULL;
    oldest_vlast=0xffffffffUL; // assuming large enough
	min_times=0xffffffffUL;
	if(rbnx_rq->num<=0){
		return NULL;
	}
	// find the entry with the oldest vlast
	for(i=0;i<rbnx_rq->num;i++){
		nse = rbnx_rq->queue[i];
		vlast = nse->vlast;
		times = nse->times;
		if(min_times>times){
			min_times = times;
			oldest_vlast = vlast;
			ret_se = nse;
		}else if(oldest_vlast>vlast && min_times==times){
			ret_se = nse;
			oldest_vlast = vlast;
		}
	}
	
	return ret_se;
}


/* Advance 1s period: if elapsed, reset rbnx_time. Caller holds rq lock. */
static void rbnx_advance_period(struct rbnx_rq *rbnx_rq, u64 now)
{
	/* Initialize period_start if not set */
	if (!rbnx_rq->rbnx_period_start) {
		rbnx_rq->rbnx_period_start = now;
		rbnx_rq->rbnx_time = 0;
		return;
	}
	
	/* Check if 1 second has elapsed */
	if (now - rbnx_rq->rbnx_period_start >= NSEC_PER_SEC) {
		rbnx_rq->rbnx_period_start = now;
		rbnx_rq->rbnx_time = 0;
	}
}

/* time_slice should be available even without CONFIG_SYSCTL */
static atomic_t time_slice = ATOMIC_INIT(10);

#ifdef CONFIG_SYSCTL

// data structure and sysctl handler for RBNX scheduling class
static int example_data = 0;
static int sched_rbnx_log(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
static int sched_rbnx_latency(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
static int sched_rbnx_tick(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
static int sched_rbnx_timeslice(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
static struct ctl_table sched_rbnx_sysctls[] = {
	{
		.procname       = "sched_rbnx_log", // -> /proc/sys/kernel/sched_rbnx_log
		.data           = &example_data,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = sched_rbnx_log,
		.extra1         = SYSCTL_ONE,
		.extra2         = SYSCTL_INT_MAX,
	},
	{
		.procname       = "sched_rbnx_latency",
		.data           = &example_data,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = sched_rbnx_latency,
		.extra1         = SYSCTL_ONE,
		.extra2         = SYSCTL_INT_MAX,
	},
	{
		.procname       = "sched_rbnx_tick",
		.data           = &example_data,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = sched_rbnx_tick,
		.extra1         = SYSCTL_ONE,
		.extra2         = SYSCTL_INT_MAX,
	},
	{
		.procname       = "sched_rbnx_timeslice",
		.data           = &example_data,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = sched_rbnx_timeslice,
		.extra1         = SYSCTL_ONE,
		.extra2         = SYSCTL_INT_MAX,
	},
	{}
};

static int __init sched_rbnx_sysctl_init(void)
{
	register_sysctl_init("kernel", sched_rbnx_sysctls);
	return 0;
}
late_initcall(sched_rbnx_sysctl_init);

/* Buffer for sched_rbnx_log: per-CPU rbnx.num and tick (debug dump). */
#define RBNX_LOG_BUF_SIZE 2048

static int sched_rbnx_log(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	static char log_str[RBNX_LOG_BUF_SIZE];
	int pos = 0;
	int cpu;
	struct rq *rq;

	if (write) {
		return -EPERM;
	}

	pos += snprintf(log_str + pos, sizeof(log_str) - pos,
			"RBNX runqueue state (num=tasks, tick):\n");
	for_each_online_cpu(cpu) {
		rq = cpu_rq(cpu);
		pos += snprintf(log_str + pos, sizeof(log_str) - pos,
				"  CPU%2d: num=%d tick=%llu\n",
				cpu, rq->rbnx.num, rq->rbnx.tick);
		if (pos >= sizeof(log_str) - 64)
			break;
	}
	pos += snprintf(log_str + pos, sizeof(log_str) - pos, "\n");

	table->data = log_str;
	table->maxlen = pos + 1;

	return proc_dostring(table, write, buffer, lenp, ppos);
}

static int sched_rbnx_timeslice(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{

	int input_value;
	static char output_buffer[RBNX_LOG_BUF_SIZE];
	if (!write) {
		// output the current time slice
		snprintf(output_buffer, sizeof(output_buffer), "%d", atomic_read(&time_slice));
		table->data = output_buffer;
		table->maxlen = strlen(output_buffer) + 1;
		return proc_dostring(table, write, buffer, lenp, ppos);
	}

	if (kstrtoint(buffer, 0, &input_value)) {
		return -EINVAL; 
	}

	if (input_value < 0 || input_value > 1000) {  
		return -EINVAL;  
	}

	atomic_set(&time_slice, input_value);

    return *lenp;
}

static int sched_rbnx_latency(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
    struct sched_rbnx_entity* rbnx_se;
    struct rq *rq;
    pid_t tid;
    struct task_struct *task;
	int input_value;
    tid = task_pid_vnr(current); 
	task = current;
	rq = task_rq(task);

	
    if (!write) {
        return -EPERM;
    }

	if (kstrtoint(buffer, 0, &input_value)) {
		return -EINVAL; 
	}

	// 更新队列
	rbnx_se = find_task_rbnx_se(&rq->rbnx, task);
	if(!rbnx_se){
		return -EINVAL;
	}
	rbnx_se->latency = input_value;


    return *lenp;
}

static int sched_rbnx_tick(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
    struct rq *rq;
    struct sched_rbnx_entity* rbnx_se;
    pid_t tid;
    struct task_struct *task;
    tid = task_pid_vnr(current);  // 获取当前线程的 tid
	task = current;
	rq = task_rq(task);

	if (!write) {
		return -EPERM;
	}

	rbnx_se = find_task_rbnx_se(&rq->rbnx, task);
	if(!rbnx_se){
		return -EINVAL; 
	}

	rbnx_se->times++;

	// printk(KERN_INFO "RBNX: Set tick of task (tid: %d) to %llu ns\n", tid, rbnx_se->vlast);

	return *lenp;
}

#endif

 static void update_curr_rbnx(struct rq *rq)
 {
	 struct task_struct *curr = rq->curr;
	 struct rbnx_rq *rbnx_rq = &rq->rbnx;
	 u64 delta_exec, now;
 
	 if (curr->sched_class != &rbnx_sched_class)
		 return;
 
	 now = rq_clock_task(rq);
	 delta_exec = now - curr->se.exec_start;
	 if (unlikely((s64)delta_exec <= 0))
		 return;
 
	rbnx_dbg("RBNX: update_curr_rbnx: task %d executed for %llu (now %llu, exec_start %llu) ns\n",
			curr->pid, delta_exec, now, curr->se.exec_start);
	 schedstat_set(curr->stats.exec_max,
			   max_t(u64, curr->stats.exec_max, delta_exec));
	 curr->se.sum_exec_runtime += delta_exec;	/* for /proc, stats */
	 curr->se.exec_start = now;			/* required next delta_exec */
 
	 rbnx_advance_period(rbnx_rq, now);
	 rbnx_rq->rbnx_time += delta_exec;
	 if (rbnx_rq->rbnx_time >= rbnx_rq->rbnx_runtime)
		 resched_curr(rq);
 }

static void enqueue_rbnx_entity(struct sched_rbnx_entity *rbnx_se, unsigned int flags){
	struct rbnx_rq* rbnx_rq;
    rbnx_rq = rbnx_rq_of_se(rbnx_se);

	/* Make sure the entity is not already on the queue */
	insert_rbnx_se(rbnx_rq, rbnx_se);
}

static void dequeue_rbnx_entity(struct sched_rbnx_entity *rbnx_se, unsigned int flags){
	struct rbnx_rq* rbnx_rq;
    rbnx_rq = rbnx_rq_of_se(rbnx_se);

	remove_rbnx_se(rbnx_rq, rbnx_se);
}

/*
 * Adding/removing a task to/from a priority array:
 */
static void
enqueue_task_rbnx(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_rbnx_entity *rbnx_se;
    rbnx_se = &p->rbnx;
	rbnx_se->vlast = rq->rbnx.tick;

	enqueue_rbnx_entity(rbnx_se, flags);
	add_nr_running(rq, 1);
}

static void dequeue_task_rbnx(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_rbnx_entity *rbnx_se;
    rbnx_se = &p->rbnx;

	update_curr_rbnx(rq);

	dequeue_rbnx_entity(rbnx_se, flags);
	sub_nr_running(rq, 1);
}

static void yield_task_rbnx(struct rq *rq)
{

}

/*
 * Preempt the current task with a newly woken task if needed:
 */
static void wakeup_preempt_rbnx(struct rq *rq, struct task_struct *p, int flags)
{
	return;
}

static struct task_struct *pick_next_task_rbnx(struct rq *rq)
{
	struct rbnx_rq *rbnx_rq = &rq->rbnx;
	struct sched_rbnx_entity *rbnx_se;
	struct task_struct *p;
	u64 now;

	/* Check if there are any runnable tasks first */
	if (rbnx_rq->num == 0)
		return NULL;

	now = rq_clock_task(rq);
	rbnx_advance_period(rbnx_rq, now);
	
	if (rbnx_rq->rbnx_time >= rbnx_rq->rbnx_runtime) {
		// rbnx_dbg("RBNX: Runtime exceeded (%llu >= %llu), skipping rbnx tasks\n", 
		//         rbnx_rq->rbnx_time, rbnx_rq->rbnx_runtime);
		return NULL;
	}

	rbnx_se = get_oldest_vlast_se(rbnx_rq);
	if (!rbnx_se) {
		return NULL;
	}
	
	rbnx_se->vlast = rbnx_rq->tick;
	rbnx_se->time_slice = atomic_read(&time_slice);

	p = rbnx_task_of(rbnx_se);
	p->se.exec_start = rq_clock_task(rq);
	return p;
}

static void put_prev_task_rbnx(struct rq *rq, struct task_struct *p)
{
	update_curr_rbnx(rq);

	update_rt_rq_load_avg(rq_clock_pelt(rq), rq, 1);
}

static inline void set_next_task_rbnx(struct rq *rq, struct task_struct *p, bool first)
{
	p->se.exec_start = rq_clock_task(rq);

	if (rq->curr->sched_class != &rbnx_sched_class)
		update_rt_rq_load_avg(rq_clock_pelt(rq), rq, 0);
}

#ifdef CONFIG_POSIX_TIMERS
static void watchdog_rbnx(struct rq *rq, struct task_struct *p)
{
	unsigned long soft, hard;

	/* max may change after cur was read, this will be fixed next tick */
	soft = task_rlimit(p, RLIMIT_RTTIME);
	hard = task_rlimit_max(p, RLIMIT_RTTIME);

	if (soft != RLIM_INFINITY) {
		unsigned long next;

		if (p->rbnx.watchdog_stamp != jiffies) {
			p->rbnx.timeout++;
			p->rbnx.watchdog_stamp = jiffies;
		}

		next = DIV_ROUND_UP(min(soft, hard), USEC_PER_SEC/HZ);
		if (p->rbnx.timeout > next) {
			posix_cputimers_rt_watchdog(&p->posix_cputimers,
						    p->se.sum_exec_runtime);
		}
	}
}
#else
static inline void watchdog_rbnx(struct rq *rq, struct task_struct *p) { }
#endif


/*
 * scheduler tick hitting a task of our scheduling class.
 *
 * NOTE: This function can be called remotely by the tick offload that
 * goes along full dynticks. Therefore no local assumption can be made
 * and everything must be accessed through the @rq and @curr passed in
 * parameters.
 */
static void task_tick_rbnx(struct rq *rq, struct task_struct *p, int queued)
{
	update_curr_rbnx(rq);

	update_rt_rq_load_avg(rq_clock_pelt(rq), rq, 1);

	rq->rbnx.tick++;
	p->rbnx.vlast=rq->rbnx.tick;
	p->rbnx.time_slice--;   // move it into /proc/sys or tick syscall
	if (p->rbnx.time_slice<=0) {
		resched_curr(rq);
	}
}

static unsigned int get_rr_interval_rbnx(struct rq *rq, struct task_struct *task)
{
	/*
	 * Time slice is 0 for SCHED_RBNX tasks
	 */
	return atomic_read(&time_slice);
}

/*
 * Priority of the task has changed. This may cause
 * us to initiate a push or pull.
 */
 // rbnx does not support priority change
static void
prio_changed_rbnx(struct rq *rq, struct task_struct *p, int oldprio)
{

}

/*
 * When switching a task to RT, we may overload the runqueue
 * with RT tasks. In this case we try to push them off to
 * other runqueues.
 */
static void switched_to_rbnx(struct rq *rq, struct task_struct *p)
{
	if (task_current(rq, p)) {
		update_rt_rq_load_avg(rq_clock_pelt(rq), rq, 0);
		return;
	}
}
#ifdef CONFIG_SMP

static void pull_rbnx_task(struct rq *this_rq);

/*
 * Pick an RBNX task on src_rq that can be pulled to this_cpu: not current,
 * allowed on this_cpu, nr_cpus_allowed > 1. Caller holds src_rq->lock (and
 * we will hold both this_rq and src_rq around the only use).
 */
static struct task_struct *pick_pullable_rbnx_task(struct rq *src_rq, int this_cpu)
{
	int i;
	struct sched_rbnx_entity *rbnx_se;
	struct task_struct *p;

	for (i = 0; i < src_rq->rbnx.num; i++) {
		rbnx_se = src_rq->rbnx.queue[i];
		p = rbnx_task_of(rbnx_se);
		if (p != src_rq->curr &&
		    p->nr_cpus_allowed > 1 &&
		    cpumask_test_cpu(this_cpu, p->cpus_ptr))
			return p;
	}
	return NULL;
}

/*
 * Try to pull one RBNX task from a busier CPU to this_rq.
 * Called with this_rq->lock held; may temporarily drop it via double_lock_balance.
 */
static void pull_rbnx_task(struct rq *this_rq)
{
	int this_cpu = this_rq->cpu;
	int cpu;
	struct rq *src_rq;
	struct task_struct *p;

	for_each_online_cpu(cpu) {
		if (cpu == this_cpu)
			continue;

		src_rq = cpu_rq(cpu);
		/* Only pull from a CPU that has more RBNX tasks than us */
		if (READ_ONCE(src_rq->rbnx.num) <= this_rq->rbnx.num+1)
			continue;

		double_lock_balance(this_rq, src_rq);

		p = pick_pullable_rbnx_task(src_rq, this_cpu);
		if (p) {
			WARN_ON(p == src_rq->curr);
			WARN_ON(!task_on_rq_queued(p));

			// rbnx_dbg("pull_rbnx_task: pull task %d from cpu%d to cpu%d\n", p->pid, src_rq->cpu, this_cpu);
			deactivate_task(src_rq, p, 0); // dequeue_task_rbnx(src_rq, p, 0);
			set_task_cpu(p, this_cpu);
			activate_task(this_rq, p, 0); // enqueue_task_rbnx(this_rq, p, 0);

			double_unlock_balance(this_rq, src_rq);
			return;
		}

		double_unlock_balance(this_rq, src_rq);
	}
}

/*
 * Try to pull RBNX tasks when we're about to schedule and the previous
 * task was not RBNX (so we may be "lowering" the runqueue and could run
 * an RBNX task if we pull one).
 */
static inline bool need_pull_rbnx_task(struct rq *rq, struct task_struct *prev)
{
	return rq->online;
}

static int balance_rbnx(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
{
	if (!on_rbnx_rq(&p->rbnx) && need_pull_rbnx_task(rq, p)) {
		rq_unpin_lock(rq, rf);
		pull_rbnx_task(rq);
		rq_repin_lock(rq, rf);
	}

	return 0;
}

static struct task_struct *pick_task_rbnx(struct rq *rq)
{

	return NULL;
}

/*
 * Select target CPU for RBNX task (fork/wakeup).
 */
static int
select_task_rq_rbnx(struct task_struct *p, int cpu, int flags)
{
	if (p->nr_cpus_allowed == 1)
		return cpumask_first(p->cpus_ptr);

	return cpu;
}

/* Assumes rq->lock is held */
static void rq_online_rbnx(struct rq *rq)
{

}

/* Assumes rq->lock is held */
static void rq_offline_rbnx(struct rq *rq)
{

}

/*
 * If we are not running and we are not going to reschedule soon, we should
 * try to push tasks away now
 */
static void task_woken_rbnx(struct rq *rq, struct task_struct *p)
{

}

/*
 * When switch from the rbnx queue, we bring ourselves to a position
 * that we might want to pull RT tasks from other runqueues.
 */
static void switched_from_rbnx(struct rq *rq, struct task_struct *p)
{

}

/* Will lock the rq it finds */
static struct rq *find_lock_lowest_rq_rbnx(struct task_struct *task, struct rq *rq)
{

	return NULL;
}

#endif

#ifdef CONFIG_SCHED_CORE
static int task_is_throttled_rbnx(struct task_struct *p, int cpu)
{
	return 0;
}
#endif

void init_rbnx_rq(struct rbnx_rq *rbnx_rq)
{
	rbnx_rq->num = 0;
	rbnx_rq->tick = 0;
	rbnx_rq->rbnx_time = 0;
	rbnx_rq->rbnx_runtime = 950 * NSEC_PER_MSEC;	/* 95% of 1s period */
	rbnx_rq->rbnx_period_start = 0;
}

DEFINE_SCHED_CLASS(rbnx) = {

	.enqueue_task		= enqueue_task_rbnx,
	.dequeue_task		= dequeue_task_rbnx,
	.yield_task		= yield_task_rbnx,

	.wakeup_preempt		= wakeup_preempt_rbnx,

	.pick_next_task		= pick_next_task_rbnx,
	.put_prev_task		= put_prev_task_rbnx,
	.set_next_task          = set_next_task_rbnx,

#ifdef CONFIG_SMP
	.balance		= balance_rbnx,
	.pick_task		= pick_task_rbnx,
	.select_task_rq		= select_task_rq_rbnx,
	.set_cpus_allowed       = set_cpus_allowed_common,
	.rq_online              = rq_online_rbnx,
	.rq_offline             = rq_offline_rbnx,
	.task_woken		= task_woken_rbnx,
	.switched_from		= switched_from_rbnx,
	.find_lock_rq		= find_lock_lowest_rq_rbnx,
#endif

	.task_tick		= task_tick_rbnx,

	.get_rr_interval	= get_rr_interval_rbnx,

	.prio_changed		= prio_changed_rbnx,
	.switched_to		= switched_to_rbnx,

	.update_curr		= update_curr_rbnx,

#ifdef CONFIG_SCHED_CORE
	.task_is_throttled	= task_is_throttled_rbnx,
#endif

#ifdef CONFIG_UCLAMP_TASK
	.uclamp_enabled		= 0, // RBNX does not support uclamp
#endif
};
