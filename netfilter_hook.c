#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>

MODULE_DESCRIPTION("My Netfilter hook");
MODULE_AUTHOR("Alex Ditu");
MODULE_LICENSE("GPL");

static struct nf_hook_ops nfho;         //struct holding set of hook function options

//function to be called by hook
unsigned int hook_func(unsigned int hooknum,
						struct sk_buff **skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
  printk(KERN_INFO "packet dropped\n");
  return NF_ACCEPT;
}




static int initialize_module(void)
{
	printk( KERN_DEBUG "Hi\n" );
	nfho.hook = hook_func;                       //function to call when conditions below met
  	nfho.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
  	nfho.pf = PF_INET;                           //IPV4 packets
  	nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  	nf_register_hook(&nfho);                     //register hook

	return 0;
}

static void clean_module(void)
{
	printk( KERN_DEBUG "Bye\n" );
	nf_unregister_hook(&nfho);                     //cleanup – unregister hook
}

module_init(initialize_module);
module_exit(clean_module);
