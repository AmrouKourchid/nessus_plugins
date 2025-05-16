#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229457);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-36886");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36886");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tipc: fix UAF in error path Sam Page
    (sam4k) working with Trend Micro Zero Day Initiative reported a UAF in the tipc_buf_append() error path:
    BUG: KASAN: slab-use-after-free in kfree_skb_list_reason+0x47e/0x4c0 linux/net/core/skbuff.c:1183 Read of
    size 8 at addr ffff88804d2a7c80 by task poc/8034 CPU: 1 PID: 8034 Comm: poc Not tainted 6.8.2 #1 Hardware
    name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-5 04/01/2014 Call Trace: <IRQ>
    __dump_stack linux/lib/dump_stack.c:88 dump_stack_lvl+0xd9/0x1b0 linux/lib/dump_stack.c:106
    print_address_description linux/mm/kasan/report.c:377 print_report+0xc4/0x620 linux/mm/kasan/report.c:488
    kasan_report+0xda/0x110 linux/mm/kasan/report.c:601 kfree_skb_list_reason+0x47e/0x4c0
    linux/net/core/skbuff.c:1183 skb_release_data+0x5af/0x880 linux/net/core/skbuff.c:1026 skb_release_all
    linux/net/core/skbuff.c:1094 __kfree_skb linux/net/core/skbuff.c:1108 kfree_skb_reason+0x12d/0x210
    linux/net/core/skbuff.c:1144 kfree_skb linux/./include/linux/skbuff.h:1244 tipc_buf_append+0x425/0xb50
    linux/net/tipc/msg.c:186 tipc_link_input+0x224/0x7c0 linux/net/tipc/link.c:1324 tipc_link_rcv+0x76e/0x2d70
    linux/net/tipc/link.c:1824 tipc_rcv+0x45f/0x10f0 linux/net/tipc/node.c:2159 tipc_udp_recv+0x73b/0x8f0
    linux/net/tipc/udp_media.c:390 udp_queue_rcv_one_skb+0xad2/0x1850 linux/net/ipv4/udp.c:2108
    udp_queue_rcv_skb+0x131/0xb00 linux/net/ipv4/udp.c:2186 udp_unicast_rcv_skb+0x165/0x3b0
    linux/net/ipv4/udp.c:2346 __udp4_lib_rcv+0x2594/0x3400 linux/net/ipv4/udp.c:2422
    ip_protocol_deliver_rcu+0x30c/0x4e0 linux/net/ipv4/ip_input.c:205 ip_local_deliver_finish+0x2e4/0x520
    linux/net/ipv4/ip_input.c:233 NF_HOOK linux/./include/linux/netfilter.h:314 NF_HOOK
    linux/./include/linux/netfilter.h:308 ip_local_deliver+0x18e/0x1f0 linux/net/ipv4/ip_input.c:254 dst_input
    linux/./include/net/dst.h:461 ip_rcv_finish linux/net/ipv4/ip_input.c:449 NF_HOOK
    linux/./include/linux/netfilter.h:314 NF_HOOK linux/./include/linux/netfilter.h:308 ip_rcv+0x2c5/0x5d0
    linux/net/ipv4/ip_input.c:569 __netif_receive_skb_one_core+0x199/0x1e0 linux/net/core/dev.c:5534
    __netif_receive_skb+0x1f/0x1c0 linux/net/core/dev.c:5648 process_backlog+0x101/0x6b0
    linux/net/core/dev.c:5976 __napi_poll.constprop.0+0xba/0x550 linux/net/core/dev.c:6576 napi_poll
    linux/net/core/dev.c:6645 net_rx_action+0x95a/0xe90 linux/net/core/dev.c:6781 __do_softirq+0x21f/0x8e7
    linux/kernel/softirq.c:553 do_softirq linux/kernel/softirq.c:454 do_softirq+0xb2/0xf0
    linux/kernel/softirq.c:441 </IRQ> <TASK> __local_bh_enable_ip+0x100/0x120 linux/kernel/softirq.c:381
    local_bh_enable linux/./include/linux/bottom_half.h:33 rcu_read_unlock_bh
    linux/./include/linux/rcupdate.h:851 __dev_queue_xmit+0x871/0x3ee0 linux/net/core/dev.c:4378
    dev_queue_xmit linux/./include/linux/netdevice.h:3169 neigh_hh_output linux/./include/net/neighbour.h:526
    neigh_output linux/./include/net/neighbour.h:540 ip_finish_output2+0x169f/0x2550
    linux/net/ipv4/ip_output.c:235 __ip_finish_output linux/net/ipv4/ip_output.c:313
    __ip_finish_output+0x49e/0x950 linux/net/ipv4/ip_output.c:295 ip_finish_output+0x31/0x310
    linux/net/ipv4/ip_output.c:323 NF_HOOK_COND linux/./include/linux/netfilter.h:303 ip_output+0x13b/0x2a0
    linux/net/ipv4/ip_output.c:433 dst_output linux/./include/net/dst.h:451 ip_local_out
    linux/net/ipv4/ip_output.c:129 ip_send_skb+0x3e5/0x560 linux/net/ipv4/ip_output.c:1492
    udp_send_skb+0x73f/0x1530 linux/net/ipv4/udp.c:963 udp_sendmsg+0x1a36/0x2b40 linux/net/ipv4/udp.c:1250
    inet_sendmsg+0x105/0x140 linux/net/ipv4/af_inet.c:850 sock_sendmsg_nosec linux/net/socket.c:730
    __sock_sendmsg linux/net/socket.c:745 __sys_sendto+0x42c/0x4e0 linux/net/socket.c:2191 __do_sys_sendto
    linux/net/socket.c:2203 __se_sys_sendto linux/net/socket.c:2199 __x64_sys_sendto+0xe0/0x1c0
    linux/net/socket.c:2199 do_syscall_x64 linux/arch/x86/entry/common.c:52 do_syscall_ ---truncated---
    (CVE-2024-36886)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36886");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "linux-aws-cloud-tools-4.15.0-1007",
     "linux-aws-headers-4.15.0-1007",
     "linux-aws-tools-4.15.0-1007",
     "linux-azure-4.15",
     "linux-cloud-tools-4.15.0-1007-aws",
     "linux-cloud-tools-4.15.0-1008-kvm",
     "linux-cloud-tools-4.15.0-20",
     "linux-cloud-tools-4.15.0-20-generic",
     "linux-cloud-tools-4.15.0-20-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-4.15",
     "linux-headers-4.15.0-1007-aws",
     "linux-headers-4.15.0-1008-kvm",
     "linux-headers-4.15.0-20",
     "linux-headers-4.15.0-20-generic",
     "linux-headers-4.15.0-20-generic-lpae",
     "linux-headers-4.15.0-20-lowlatency",
     "linux-image-4.15.0-1007-aws",
     "linux-image-4.15.0-1007-aws-dbgsym",
     "linux-image-4.15.0-1008-kvm",
     "linux-image-4.15.0-1008-kvm-dbgsym",
     "linux-image-unsigned-4.15.0-20-generic",
     "linux-image-unsigned-4.15.0-20-generic-dbgsym",
     "linux-image-unsigned-4.15.0-20-generic-lpae",
     "linux-image-unsigned-4.15.0-20-generic-lpae-dbgsym",
     "linux-image-unsigned-4.15.0-20-lowlatency",
     "linux-kvm-cloud-tools-4.15.0-1008",
     "linux-kvm-headers-4.15.0-1008",
     "linux-kvm-tools-4.15.0-1008",
     "linux-libc-dev",
     "linux-modules-4.15.0-1007-aws",
     "linux-modules-4.15.0-1008-kvm",
     "linux-modules-4.15.0-20-generic",
     "linux-modules-4.15.0-20-generic-lpae",
     "linux-modules-4.15.0-20-lowlatency",
     "linux-modules-extra-4.15.0-1007-aws",
     "linux-modules-extra-4.15.0-1008-kvm",
     "linux-modules-extra-4.15.0-20-generic",
     "linux-modules-extra-4.15.0-20-generic-lpae",
     "linux-modules-extra-4.15.0-20-lowlatency",
     "linux-oracle",
     "linux-source-4.15.0",
     "linux-tools-4.15.0-1007-aws",
     "linux-tools-4.15.0-1008-kvm",
     "linux-tools-4.15.0-20",
     "linux-tools-4.15.0-20-generic",
     "linux-tools-4.15.0-20-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "18.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-hwe",
     "linux-azure",
     "linux-gcp",
     "linux-hwe",
     "linux-kvm",
     "linux-oracle"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "16.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "kernel-rt",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "9"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
