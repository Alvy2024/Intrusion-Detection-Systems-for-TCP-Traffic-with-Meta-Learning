#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>

#define DEVICE_NAME "packet_sniffer"
#define PROC_ENTRY_NAME "packet_data"

// Shared memory area to store captured packet information
static char packet_buffer[1024];
static unsigned long packet_length = 0;

// Device file related
static struct proc_dir_entry *entry;

// Capture packets and store information
static unsigned int packet_capture_callback(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    char packet_info[256];
    
    eth = (struct ethhdr *)skb_mac_header(skb);
    if (eth->h_proto == htons(ETH_P_IP)) {
        ip = (struct iphdr *)skb_network_header(skb);
        
        // Process IP packet
        snprintf(packet_info, sizeof(packet_info), "SRC: %pI4 DST: %pI4\n",
                 &ip->saddr, &ip->daddr);
        
        // Process transport layer protocols: TCP or UDP
        if (ip->protocol == IPPROTO_TCP) {
            tcp = (struct tcphdr *)skb_transport_header(skb);
            snprintf(packet_info + strlen(packet_info), sizeof(packet_info) - strlen(packet_info),
                     "Protocol: TCP, SRC Port: %u DST Port: %u\n",
                     ntohs(tcp->source), ntohs(tcp->dest));
        } else if (ip->protocol == IPPROTO_UDP) {
            udp = (struct udphdr *)skb_transport_header(skb);
            snprintf(packet_info + strlen(packet_info), sizeof(packet_info) - strlen(packet_info),
                     "Protocol: UDP, SRC Port: %u DST Port: %u\n",
                     ntohs(udp->source), ntohs(udp->dest));
        }

        // Store information into the buffer
        if (packet_length + strlen(packet_info) < sizeof(packet_buffer)) {
            strncpy(packet_buffer + packet_length, packet_info, strlen(packet_info));
            packet_length += strlen(packet_info);
        }
    }
    
    return NF_ACCEPT;
}

// Initialize the module
static int __init packet_sniffer_init(void)
{
    struct nf_hook_ops *nfho = NULL;

    // Create proc file
    entry = proc_create(PROC_ENTRY_NAME, 0666, NULL, &packet_buffer);
    if (!entry) {
        printk(KERN_ERR "Failed to create proc entry\n");
        return -ENOMEM;
    }

    // Set up hook operations
    nfho = (struct nf_hook_ops *)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (!nfho) {
        printk(KERN_ERR "Failed to allocate memory for nf_hook_ops\n");
        return -ENOMEM;
    }

    nfho->hook = packet_capture_callback;
    nfho->hooknum = NF_INET_PRE_ROUTING;
    nfho->pf = PF_INET;
    nfho->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, nfho);

    printk(KERN_INFO "Packet sniffer initialized\n");
    return 0;
}

// Exit the module
static void __exit packet_sniffer_exit(void)
{
    remove_proc_entry(PROC_ENTRY_NAME, NULL);
    printk(KERN_INFO "Packet sniffer removed\n");
}

module_init(packet_sniffer_init);
module_exit(packet_sniffer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alvy");
MODULE_DESCRIPTION("A simple packet sniffer for Linux kernel.");
