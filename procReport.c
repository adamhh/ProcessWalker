/**
 * TCSS422 Assignment 3 - Page Table Walker
 * University of Washington - Winter 2021
 * 
 * This program creates a kernel module that traverses the list
 * of running processes and outputs a Process Report in CSV format
 * that displays information (ID, Name, Contiguous Pages, Non-Contiguous
 * Pages, and Total Pages).
 *
 * Run Instructions (as I feel this program warrants ellaboration)
 *  Build kernel module: 'cd procReport/ && make'
 *  View output in CSV list: 'cat /proc/proc_report'
 *  
 *  To remove previously installed module: 'sudo rmmod ./procReport.ko'
 *  To install a new  module and create process snapshot: 
 *    'sudo insmod ./procReport.ko'
 * 
 * @author Adam H. Hall
 * @version 1
 */
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

/** Initialize process data to use for ouput **/
typedef struct MyData {
	int proc_id;
	char *proc_name;
	int contig_pages;
	int noncontig_pages;
  	struct MyData *next;
} MyData;

/** Global variables **/
typedef struct CountData {
	MyData *head;
 	int contig_count;
  	int noncontig_count;
} CountData;

/** Global struct **/
CountData CountHead;

/** Declare functions **/
int p_initialize(void);
unsigned long virt2phys(struct mm_struct*, unsigned long);
static void generate_list(void);
static int proc_open(struct inode *, struct file *);
static int proc_print(struct seq_file *, void *);
void proc_free(void);

/** Define proc_open prior to being called **/
static const struct proc_ops proc_fops = {
	.proc_open = proc_open,
  	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/**
 * Create a list of all the processes
 * and a report about the processes and output
 *  to /proc/proc_report and /var/log/syslog
 **/
int p_initialize (void) {
	generate_list();
  	proc_create("proc_report", 0, NULL, &proc_fops); 
  	return 0;
}

/** Virtual address to physical address  **/
unsigned long virt2phys(struct mm_struct *MemStruct, unsigned long vPage) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        struct page *page;
        unsigned long physical_page_addr;  
        pgd = pgd_offset(MemStruct, vPage);

        if(pgd_none(*pgd) || pgd_bad(*pgd)) {
          return 0;
        }
        p4d = p4d_offset(pgd, vPage);

        if(p4d_none(*p4d) || p4d_bad(*p4d)) {
          return 0;
        }
        pud = pud_offset(p4d, vPage);
  
        if(pud_none(*pud) || pud_bad(*pud)) {
          return 0;
        }
        pmd = pmd_offset(pud, vPage);

        if(pmd_none(*pmd) || pmd_bad(*pmd)) {
          return 0;
        }
        if(!(pte = pte_offset_map(pmd, vPage))) {
          return 0;
        }

        if(!(page = pte_page(*pte)))  {
          return 0;
        }

        physical_page_addr = page_to_pfn(page);
        pte_unmap(pte);
	//handle unmapped page
	if (physical_page_addr==70368744173568) {
	  return 0;
	}
        return physical_page_addr;
}


/**
 * Create a linked list of MyData nodes
 * for processes with PID > 650 
 **/
static void generate_list(void) {
	struct task_struct *task;
 	struct vm_area_struct *vma;
  	unsigned long prev, vPage;
  	MyData *temp;

  	// init temp proc node and set next val
  	temp = kmalloc(sizeof(MyData), GFP_KERNEL);
  	temp->next = NULL;
  
  	// save into LL
  	CountHead.head = temp;
  	prev = 0;
  
  	//only grab processess with PID > 650
  	for_each_process(task) {
	  if(task->pid > 650) {
     	    temp->proc_id = task->pid;
      	    temp->proc_name = task->comm;
            temp->contig_pages = 0;
      	    temp->noncontig_pages = 0;
      	    vma = 0;

      	    if (task->mm && task->mm->mmap) {
              for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
                for (vPage = vma->vm_start; vPage < vma->vm_end; vPage += PAGE_SIZE) {
                  unsigned long physical_page_addr = virt2phys(task->mm, vPage);
                  if(physical_page_addr) {
                    (physical_page_addr == prev + PAGE_SIZE)? temp->contig_pages++ : temp->noncontig_pages++;
                    prev = physical_page_addr;
                  }
                }
              }
              CountHead.contig_count += temp->contig_pages;
              CountHead.noncontig_count += temp->noncontig_pages;  
            }
	    //allocate memory for next node
            temp->next = kmalloc(sizeof(MyData), GFP_KERNEL);
            temp = temp->next;
      	  }
	} 
	// Free temp
  	temp->next = NULL;
  	temp = NULL;
	kfree(temp);
}


/** Create and write to file in /proc/proc_report **/
static int proc_open(struct inode *inode, struct file *file) {
	return single_open(file, proc_print, NULL);
}

/**
 *  Print process report to var/syslog and to
 *  /proc/proc_report as a CSV list
 **/
static int proc_print(struct seq_file *m, void *v) {
	MyData *temp = CountHead.head;
  	printk(KERN_INFO "PROCESS REPORT:\n");
  	printk(KERN_INFO "proc_id,proc_name,contig_pages,noncontig_pages,total_pages\n");
  	seq_printf(m, "PROCESS REPORT:\n");
  	seq_printf(m,"%s,%s,%s,%s,%s\n" ,"proc_id", "proc_name", "contig_pages", "noncontig_pages", "total_pages");

 	while(temp->next) {
    	  seq_printf(m, "%d,%s,%d,%d,%d\n", temp->proc_id, temp->proc_name, temp->contig_pages, temp->noncontig_pages, temp->contig_pages + temp->noncontig_pages);
    	  printk(KERN_INFO "%d,%s,%d,%d,%d\n", temp->proc_id, temp->proc_name, temp->contig_pages, temp->noncontig_pages, temp->contig_pages + temp->noncontig_pages);
    	  temp = temp->next;  
 	}

  	seq_printf(m, "%s,,%d,%d,%d\n", "TOTALS", CountHead.contig_count, CountHead.noncontig_count, CountHead.contig_count + CountHead.noncontig_count);
  	printk(KERN_INFO "%s,,%d,%d,%d\n", "TOTALS", CountHead.contig_count, CountHead.noncontig_count, CountHead.contig_count + CountHead.noncontig_count);
  	return 0;
}


/** Close kernel process and free memory  **/
void proc_free(void) {
	MyData *temp;
        //iterate and free
        while(CountHead.head) {
          temp = CountHead.head->next;
          kfree(CountHead.head);
          CountHead.head = temp;
        }
	remove_proc_entry("proc_report", NULL);
  	
}

// Derivate of linux kernel so GPL and to remove compile warning
MODULE_LICENSE("GPL");
module_init(p_initialize);
module_exit(proc_free);
