// SPDX-License-Identifier: GPL-2.0
/*
 * Robonix Scheduling Class (mapped to the SCHED_FIFO and SCHED_RR
 * policies)
 */
#include <linux/atomic.h>

static inline struct task_struct *rbnx_task_of(struct sched_rbnx_entity *rbnx_se)
{
	return container_of(rbnx_se, struct task_struct, rbnx);
}

static inline struct rq *rq_of_rbnx_rq(struct rbnx_rq *rbnx_rq)
{
	return container_of(rbnx_rq, struct rq, rbnx);
}

static inline struct rq *rq_of_rbnx_se(struct sched_rbnx_entity *rbnx_se)
{
	struct task_struct *p = rbnx_task_of(rbnx_se);

	return task_rq(p);
}

static inline struct rbnx_rq *rbnx_rq_of_se(struct sched_rbnx_entity *rbnx_se)
{
	struct rq *rq = rq_of_rbnx_se(rbnx_se);

	return &rq->rbnx;
}

inline void insert_rbnx_se(struct rbnx_rq* rbnx_rq, struct sched_rbnx_entity * rbnx_se){
	rbnx_rq->queue[rbnx_rq->num] = rbnx_se;
	rbnx_rq->num++;
}

inline void remove_rbnx_se(struct rbnx_rq* rbnx_rq, struct sched_rbnx_entity * rbnx_se){
	int i=0;
	if(rbnx_rq->num<=0){
		return;
	}
	for(;i<rbnx_rq->num;i++){
		if(rbnx_rq->queue[i]==rbnx_se){
			break;
		}
	}
	rbnx_rq->num--;
	for(;i<rbnx_rq->num;i++){
		rbnx_rq->queue[i]=rbnx_rq->queue[i+1];
	}
}

inline struct sched_rbnx_entity * find_task_rbnx_se(struct rbnx_rq* rbnx_rq, struct task_struct* task){
	int i=0;
	if(rbnx_rq->num<=0){
		return NULL;
	}
	for(;i<rbnx_rq->num;i++){
		struct sched_rbnx_entity* nse = rbnx_rq->queue[i];
		struct task_struct* ntask = rbnx_task_of(nse);
		if(ntask==task){
			return nse;
		}
	}

	return NULL;
}

// [Important]: 
// choose the sched_rbnx_entity with the oldest vlast
inline struct sched_rbnx_entity* get_oldest_vlast_se(struct rbnx_rq* rbnx_rq){
	int i=0;
	struct sched_rbnx_entity* ret_se=NULL;
	unsigned long long oldest_vlast=0xffffffffUL; // assuming large enough
	if(rbnx_rq->num<=0){
		return NULL;
	}
	for(;i<rbnx_rq->num;i++){
		struct sched_rbnx_entity* nse = rbnx_rq->queue[i];
		unsigned long long vlast = nse->vlast;

		if(oldest_vlast>vlast){
			ret_se = nse;
			oldest_vlast = vlast;
		}
	}
	
	return ret_se;
}


#ifdef CONFIG_SYSCTL

// data structure and sysctl handler for RBNX scheduling class
static int example_data = 0;
static atomic_t counter = ATOMIC_INIT(0);
static int sched_rbnx_log(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
static int sched_rbnx_latency(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
static int sched_rbnx_tick(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
static struct ctl_table sched_rbnx_sysctls[] = {
	{
		.procname       = "sched_rbnx_log",
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
	{}
};

static int __init sched_rbnx_sysctl_init(void)
{
	register_sysctl_init("kernel", sched_rbnx_sysctls);
	return 0;
}
late_initcall(sched_rbnx_sysctl_init);

static int sched_rbnx_log(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
    static char log_str[64];  // 足够大的缓冲区存储数字
    
    if (write) {
        return -EPERM;
    }
    
    // 将 counter 的值格式化到字符串中
    // snprintf(log_str, sizeof(log_str), "counter value: %d\n", atomic_read(&counter));
    
    table->data = log_str;
    table->maxlen = strlen(log_str) + 1;  // 包含终止符
    
    return proc_dostring(table, write, buffer, lenp, ppos);
}

static int sched_rbnx_latency(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	int input_value;
    pid_t tid = task_pid_vnr(current); 
	struct task_struct *task = current;
	struct rq *rq = task_rq(task);

	
    if (!write) {
        return -EPERM;
    }

	if (kstrtoint(buffer, 0, &input_value)) {
		return -EINVAL; 
	}

	// 检查输入值是否合法
	if (input_value < 0 || input_value > 1000) {  
		return -EINVAL;  
	}

	// 更新队列
	struct sched_rbnx_entity* rbnx_se = find_task_rbnx_se(&rq->rbnx, task);
	if(!rbnx_se){
		return -EINVAL;
	}
	rbnx_se->latency = input_value;

	// 打印日志
	// printk(KERN_INFO "RBNX: Set latency of task (tid: %d) to %d ns\n", tid, input_value);

    return *lenp;
}

static int sched_rbnx_tick(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
    pid_t tid = task_pid_vnr(current);  // 获取当前线程的 tid
	struct task_struct *task = current;
	struct rq *rq = task_rq(task);

	if (!write) {
		return -EPERM;
	}

	// 更新队列
	struct sched_rbnx_entity* rbnx_se = find_task_rbnx_se(&rq->rbnx, task);
	if(!rbnx_se){
		return -EINVAL; 
	}
	rbnx_se->vlast++;

	// 打印日志
	printk(KERN_INFO "RBNX: Set tick of task (tid: %d) to %llu ns\n", tid, rbnx_se->vlast);

	return *lenp;
}

#endif

static void enqueue_rbnx_entity(struct sched_rbnx_entity *rbnx_se, unsigned int flags){
	struct rbnx_rq* rbnx_rq = rbnx_rq_of_se(rbnx_se);

	// 调度统计信息获取,暂时不实现
	atomic_add(1, &counter);

	insert_rbnx_se(rbnx_rq, rbnx_se);
}

static void dequeue_rbnx_entity(struct sched_rbnx_entity *rbnx_se, unsigned int flags){
	struct rbnx_rq* rbnx_rq = rbnx_rq_of_se(rbnx_se);

	// 调度统计信息获取,暂时不实现
	atomic_sub(1, &counter);
	remove_rbnx_se(rbnx_rq, rbnx_se);
}

/*
 * Adding/removing a task to/from a priority array:
 */
static void
enqueue_task_rbnx(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_rbnx_entity *rbnx_se = &p->rbnx;

	// 调度统计信息获取,暂时不实现
	// check_schedstat_required();
	// update_stats_wait_start_rbnx(rbnx_rq_of_se(rbnx_se), rbnx_se);

	enqueue_rbnx_entity(rbnx_se, flags);

	// 暂时不考虑迁移
	// if (!task_current(rq, p) && p->nr_cpus_allowed > 1)
	// 	enqueue_pushable_task(rq, p);
}

static void dequeue_task_rbnx(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_rbnx_entity *rbnx_se = &p->rbnx;

	dequeue_rbnx_entity(rbnx_se, flags);

	// 暂时不考虑迁移
	// dequeue_pushable_task(rq, p);
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
	struct sched_rbnx_entity *rbnx_se = get_oldest_vlast_se(&rq->rbnx);
	if(!rbnx_se){
		return NULL;
	}
	rbnx_se->vlast = rq->rbnx.tick; // update vlast to the oldest value
	rbnx_se->time_slice = 1;
	return rbnx_task_of(rbnx_se);
}

static void put_prev_task_rbnx(struct rq *rq, struct task_struct *p)
{

}

static inline void set_next_task_rbnx(struct rq *rq, struct task_struct *p, bool first)
{
	
}

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
	watchdog(rq, p);

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
	return 0;
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

}

/*
 * Update the current task's runtime statistics. Skip current tasks that
 * are not in our scheduling class.
 */
static void update_curr_rbnx(struct rq *rq)
{

}

#ifdef CONFIG_SMP
static int balance_rbnx(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
{
	return 0;
}

static struct task_struct *pick_task_rbnx(struct rq *rq)
{

	return NULL;
}

static int
select_task_rq_rbnx(struct task_struct *p, int cpu, int flags)
{
	return 0; // should return target cpu's number
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

void init_rbnx_rq(struct rbnx_rq *rbnx_rq){
	rbnx_rq->num = 0;
	rbnx_rq->tick = 0;
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
