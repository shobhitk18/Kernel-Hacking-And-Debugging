#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/rwsem.h>
#include "common.h"
#include <linux/list.h>
#include <linux/dma-buf.h>
#include <linux/fdtable.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/ptrace.h>
#include <linux/scatterlist.h>

#define LARGE_SIZE		1024

asmlinkage extern long (*sysptr)(int id);

static spinlock_t test_spin_lock1 = __SPIN_LOCK_UNLOCKED();
static DEFINE_MUTEX(test_mutex_lock1);
static DEFINE_MUTEX(test_mutex_lock2);

static RAW_NOTIFIER_HEAD(my_notifier_chain);

struct my_list {
	struct list_head list;
	int data;
};

void trigger_kernel_mem_leak(void)
{
	char *buff = NULL;

	buff = kmalloc(1000000, GFP_KERNEL);
	if (!buff)
		pr_info("Unable to allocate memory\n");
}

static int t2_func(void *unused)
{
	int ret;

	ssleep(1);
	pr_info("Thread 2 Started\n");

	pr_info("Grabbing lock2 by  thread2\n");
	mutex_lock(&test_mutex_lock2);

	if (mutex_is_locked(&test_mutex_lock2))
		pr_info("thread 2 is holding Lock 2\n");
	pr_info("Grabbing lock1 by  thread2\n");

	ret = mutex_lock_interruptible(&test_mutex_lock1);
	if (mutex_is_locked(&test_mutex_lock1))
		pr_info("thread 2 is holding Lock 1\n");

	mutex_unlock(&test_mutex_lock1);
	if (!mutex_is_locked(&test_mutex_lock1))
		pr_info("thread 2 released lock 1\n");

	mutex_unlock(&test_mutex_lock2);
	if (!mutex_is_locked(&test_mutex_lock2))
		pr_info("thread 2 released lock 2\n");

	pr_info("Stopping Thread 2\n");

	do_exit(0);
}

static int t1_func(void *unused)
{
	int ret;

	pr_info("Thread 1 Started");

	pr_info("Grabbing lock1 by  thread1\n");
	mutex_lock(&test_mutex_lock1);
	if (mutex_is_locked(&test_mutex_lock1))
		pr_info("thread 1 is holding Lock 1\n");

	ssleep(2);

	pr_info("Grabbing lock2 by  thread1\n");
	ret = mutex_lock_interruptible(&test_mutex_lock2);
	if (mutex_is_locked(&test_mutex_lock2))
		pr_info("thread 1 is holding Lock 2\n");

	mutex_unlock(&test_mutex_lock2);
	if (!mutex_is_locked(&test_mutex_lock2))
		pr_info("thread 1 released lock 2\n");

	mutex_unlock(&test_mutex_lock1);
	if (!mutex_is_locked(&test_mutex_lock1))
		pr_info("thread 1 released lock 1\n");

	pr_info("Stopping Thread 1\n");
	do_exit(0);
}

void trigger_deadlock(void)
{
	struct task_struct *t1 = NULL;
	struct task_struct *t2 = NULL;

	pr_info("inside trigger deadlock\n");
	t1 = kthread_create(t1_func, NULL, "thread1");
	if (!t1) {
		pr_info("cannot create thread 1");
		return;
	}
	pr_info("thread 1 created");

	t2 = kthread_create(t2_func, NULL, "thread2");
	if (!t2) {
		pr_info("cannot create thread 2");
		return;
	}
	pr_info("thread 2 created");

	wake_up_process(t1);
	wake_up_process(t2);

	ssleep(5);
	force_sig(9, t1);

}

void trigger_sleep_inside_atomic_section(void)
{
	char *ar = NULL;

	pr_info("inside trigger sleep inside atomic section\n");

	spin_lock(&test_spin_lock1);
	if (spin_is_locked(&test_spin_lock1))
		pr_info("current thread is holding spin Lock 1\n");

	ar = kmalloc(10000, GFP_KERNEL);

	spin_unlock(&test_spin_lock1);
	if (!spin_is_locked(&test_spin_lock1))
		pr_info("current thread released spin lock 1\n");

	kfree(ar);
}

void trigger_bug_rw_semaphore(void)
{
	struct rw_semaphore rwsem;
	int data = 0;

	init_rwsem(&rwsem);
	pr_info("Initialized read-write semaphore\n");

	down_read(&rwsem);
	pr_info("Got the Semaphore in read mode\n");

	data = data + 1;

	pr_info("Going to Sleep\n");
	ssleep(2);

	up_write(&rwsem);
	pr_info("Releasing the Semaphore in Write mode\n");
}

struct mystruct {
	int a;
	struct list_head list;
};

void trigger_list_corruption(void)
{
	int i = 0;
	struct mystruct obj;
	struct mystruct *tmp;

	INIT_LIST_HEAD(&(obj.list));
	for (i = 0; i < 5; i++) {
		tmp = kmalloc(sizeof(struct mystruct), GFP_KERNEL);
		tmp->a = i+1;
		list_add_tail(&(tmp->list), &(obj.list));
	}

	tmp->list.next = (void *)0xDEADBEEF;
	tmp = kmalloc(sizeof(struct mystruct), GFP_KERNEL);
	list_add_tail(&(tmp->list), &(obj.list));

}

void trigger_cred_management(void)
{
	const struct cred *curr_cred, *new_cred;

	curr_cred = get_current_cred();
	new_cred = prepare_creds();
	put_cred(new_cred);
	put_cred(new_cred);
}

//https://stackoverflow.com/a/49508131/2802539
long currentTimeMillis(void)
{
	struct timespec time;

	getnstimeofday(&time);
	return time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

void trigger_soft_lockup(void)
{
	long start = 0, curr = 0;
	long elapsed_time = 0;

	start = currentTimeMillis();
	while (1) {
		curr = currentTimeMillis();
		elapsed_time = (curr - start)/1000;
		if (elapsed_time > 30)
			break;
	}
	pr_info("SoftLock Done\n");
}

static struct device dev = {
	.init_name = "mydevice",
	.coherent_dma_mask = ~0,
	.dma_mask = &dev.coherent_dma_mask,
};

void trigger_bug_dma_api(void)
{
	void *kbuf = NULL;
	size_t size = 100;
	dma_addr_t handle;
	int ret;

	ret = device_register(&dev);

	kbuf = dma_alloc_coherent(&dev, size, &handle, GFP_KERNEL);
	dma_free_coherent(NULL, size, kbuf, handle);
}


int event_handler(struct notifier_block *self, unsigned long val, void *data)
{
	return NOTIFY_OK;
}

static struct notifier_block notifier = {
	.notifier_call = 0,
};

static int trigger_invalid_notifier(void)
{
	pr_info("Registering notifier with invalid handler\n");
	raw_notifier_chain_register(&my_notifier_chain, &notifier);
	pr_info("Publishing event to all the notifiers\n");
	raw_notifier_call_chain(&my_notifier_chain, 10, NULL);
	raw_notifier_chain_unregister(&my_notifier_chain, &notifier);
	return 0;
}

int trigger_sg_issue(void)
{

	struct scatterlist sg1[5], sg2;

	sg_init_table(sg1, 4);
	sg_init_table(&sg2, 1);
	sg_chain(&sg1[0], 4, &sg2);
	pr_info("The Page could not be assigned to a scatterlist that points to another scatterlist\n");
	sg_assign_page(&sg1[3], 0);
	return 0;
}

int trigger_slab_verifier(void)
{
	char *ar = kmalloc(10, GFP_KERNEL);

	kfree(ar);
	strcpy(ar, "abc");
	return 0;
}

static int th2_func(void *unused)
{
	pr_info("Thread 2 Started\n");

	pr_info("Grabbing lock2 by  thread2\n");
	mutex_lock(&test_mutex_lock2);
	if (mutex_is_locked(&test_mutex_lock2))
		pr_info("thread 2 is holding Lock 2\n");

	pr_info("Grabbing lock1 by  thread2\n");
	mutex_lock(&test_mutex_lock1);
	if (mutex_is_locked(&test_mutex_lock1))
		pr_info("thread 2 is holding Lock 1\n");

	mutex_unlock(&test_mutex_lock1);
	if (!mutex_is_locked(&test_mutex_lock1))
		pr_info("thread 2 released lock 1\n");

	mutex_unlock(&test_mutex_lock2);
	if (!mutex_is_locked(&test_mutex_lock2))
		pr_info("thread 2 released lock 2\n");

	pr_info("Stopping Thread 2\n");
	do_exit(0);
}

static int th1_func(void *unused)
{
	pr_info("Thread 1 Started");

	pr_info("Grabbing lock1 by  thread1\n");
	mutex_lock(&test_mutex_lock1);
	if (mutex_is_locked(&test_mutex_lock1))
		pr_info("thread 1 is holding Lock 1\n");

	ssleep(5);

	pr_info("Grabbing lock2 by  thread1\n");
	mutex_lock(&test_mutex_lock2);
	if (mutex_is_locked(&test_mutex_lock2))
		pr_info("thread 1 is holding Lock 2\n");

	mutex_unlock(&test_mutex_lock2);
	if (!mutex_is_locked(&test_mutex_lock2))
		pr_info("thread 1 released lock 2\n");

	mutex_unlock(&test_mutex_lock1);
	if (!mutex_is_locked(&test_mutex_lock1))
		pr_info("thread 1 released lock 1\n");

	pr_info("Stopping Thread 1\n");
	do_exit(0);
}

void trigger_hung_task(void)
{
	struct task_struct *t1 = NULL;
	struct task_struct *t2 = NULL;

	pr_info("inside trigger deadlock\n");
	t1 = kthread_create(th1_func, NULL, "thread1");
	if (!t1) {
		pr_info("cannot create thread 1");
		return;
	}
	pr_info("thread 1 created");

	t2 = kthread_create(th2_func, NULL, "thread2");
	if (!t2) {
		pr_info("cannot create thread 2");
		return;
	}
	pr_info("thread 2 created");

	wake_up_process(t1);
	wake_up_process(t2);
}

int poison_page_flag(void)
{
	struct page *page;
	unsigned int order = 0;
	static unsigned long gpb_mask = GFP_KERNEL;

	pr_info("inside %s\n", __func__);

	pr_info("Allocating 1 page\n");
	page = alloc_pages(gpb_mask, order);
	pr_info("Page is allocated. Refcount :  %d\n", page_ref_count(page));
	//poisoning the flag
	page->flags = -1l;

	pr_info("Freeing allocated page\n");
	free_page((unsigned long) page_address(page));
	pr_info("Exiting poison_page.\n");
	return 0;
}


/* Main Entry Point for the SYSCALL */
asmlinkage long sys_trigger_bug(int id)
{
	int ret = 0;

	pr_info("TRIGGER_BUG::trigger_bug received id %d\n", id);
	if (id <= 0) {
		pr_info("Returning error\n");
		ret = -EINVAL;
		goto out;
	}

	switch (id) {
	case BUG_RW_SEMAPHORE:
		pr_info("triggering BUG_RW_SEMAPHORE\n");
		trigger_bug_rw_semaphore();
		break;
	case BUG_SLEEP_INSIDE_ATOMIC_SECTION:
		pr_info("triggering sleep inside atomic section\n");
		trigger_sleep_inside_atomic_section();
		break;
	case BUG_KERNEL_MEM_LEAK:
		pr_info("Triggering kernel memory leak\n");
		trigger_kernel_mem_leak();
		break;
	case BUG_DEBUG_VM_PAGE:
		pr_info("Trigger debug virtual memory bug\n");
		poison_page_flag();
		break;
	case BUG_DEADLOCK:
		pr_info("triggering spinlock deadlock\n");
		trigger_deadlock();
		break;
	case BUG_SOFT_LOCKUP:
		pr_info("triggering bug softlockup\n");
		trigger_soft_lockup();
		break;
	case BUG_LINKED_LIST_CORRUPTION:
		pr_info("triggering list corruption\n");
		trigger_list_corruption();
		break;
	case BUG_DMA_API:
		pr_info("triggering bug dma api\n");
		trigger_bug_dma_api();
		break;
	case BUG_INVALID_NOTIFIER:
		pr_info("Triggering invalid notifier bug\n");
		trigger_invalid_notifier();
		break;
	case BUG_SCATTERLIST_CHAINED:
		pr_info("Triggering bug on scattelist being chained\n");
		trigger_sg_issue();
		break;
	case SLAB_VALIDATOR:
		pr_info("Triggering incorrect memory access\n");
		trigger_slab_verifier();
		break;
	case BUG_HUNG_TASK:
		trigger_hung_task();
		break;
	case BUG_CRED_MANAGEMENT:
		pr_info("Trigger credential management bug\n");
		trigger_cred_management();
		break;
	default:
		pr_info("Invalid bug id sent from user program\n");
}
out:
	return 0;
}

static int __init init_sys_trigger_bug(void)
{
	pr_info("installed new sys_trigger_bug module\n");
	if (sysptr == NULL)
		sysptr = sys_trigger_bug;
	return 0;
}

static void  __exit exit_sys_trigger_bug(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	pr_info("removed sys_trigger_bug module\n");
}

module_init(init_sys_trigger_bug);
module_exit(exit_sys_trigger_bug);
MODULE_LICENSE("GPL");
