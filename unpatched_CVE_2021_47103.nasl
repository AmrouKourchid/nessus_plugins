#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229791);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2021-47103");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47103");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: inet: fully convert sk->sk_rx_dst to
    RCU rules syzbot reported various issues around early demux, one being included in this changelog [1]
    sk->sk_rx_dst is using RCU protection without clearly documenting it. And following sequences in
    tcp_v4_do_rcv()/tcp_v6_do_rcv() are not following standard RCU rules. [a] dst_release(dst); [b]
    sk->sk_rx_dst = NULL; They look wrong because a delete operation of RCU protected pointer is supposed to
    clear the pointer before the call_rcu()/synchronize_rcu() guarding actual memory freeing. In some cases
    indeed, dst could be freed before [b] is done. We could cheat by clearing sk_rx_dst before calling
    dst_release(), but this seems the right time to stick to standard RCU annotations and debugging
    facilities. [1] BUG: KASAN: use-after-free in dst_check include/net/dst.h:470 [inline] BUG: KASAN: use-
    after-free in tcp_v4_early_demux+0x95b/0x960 net/ipv4/tcp_ipv4.c:1792 Read of size 2 at addr
    ffff88807f1cb73a by task syz-executor.5/9204 CPU: 0 PID: 9204 Comm: syz-executor.5 Not tainted
    5.16.0-rc5-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google
    01/01/2011 Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0xcd/0x134
    lib/dump_stack.c:106 print_address_description.constprop.0.cold+0x8d/0x320 mm/kasan/report.c:247
    __kasan_report mm/kasan/report.c:433 [inline] kasan_report.cold+0x83/0xdf mm/kasan/report.c:450 dst_check
    include/net/dst.h:470 [inline] tcp_v4_early_demux+0x95b/0x960 net/ipv4/tcp_ipv4.c:1792
    ip_rcv_finish_core.constprop.0+0x15de/0x1e80 net/ipv4/ip_input.c:340
    ip_list_rcv_finish.constprop.0+0x1b2/0x6e0 net/ipv4/ip_input.c:583 ip_sublist_rcv net/ipv4/ip_input.c:609
    [inline] ip_list_rcv+0x34e/0x490 net/ipv4/ip_input.c:644 __netif_receive_skb_list_ptype
    net/core/dev.c:5508 [inline] __netif_receive_skb_list_core+0x549/0x8e0 net/core/dev.c:5556
    __netif_receive_skb_list net/core/dev.c:5608 [inline] netif_receive_skb_list_internal+0x75e/0xd80
    net/core/dev.c:5699 gro_normal_list net/core/dev.c:5853 [inline] gro_normal_list net/core/dev.c:5849
    [inline] napi_complete_done+0x1f1/0x880 net/core/dev.c:6590 virtqueue_napi_complete
    drivers/net/virtio_net.c:339 [inline] virtnet_poll+0xca2/0x11b0 drivers/net/virtio_net.c:1557
    __napi_poll+0xaf/0x440 net/core/dev.c:7023 napi_poll net/core/dev.c:7090 [inline]
    net_rx_action+0x801/0xb40 net/core/dev.c:7177 __do_softirq+0x29b/0x9c2 kernel/softirq.c:558 invoke_softirq
    kernel/softirq.c:432 [inline] __irq_exit_rcu+0x123/0x180 kernel/softirq.c:637 irq_exit_rcu+0x5/0x20
    kernel/softirq.c:649 common_interrupt+0x52/0xc0 arch/x86/kernel/irq.c:240 asm_common_interrupt+0x1e/0x40
    arch/x86/include/asm/idtentry.h:629 RIP: 0033:0x7f5e972bfd57 Code: 39 d1 73 14 0f 1f 80 00 00 00 00 48 8b
    50 f8 48 83 e8 08 48 39 ca 77 f3 48 39 c3 73 3e 48 89 13 48 8b 50 f8 48 89 38 49 8b 0e <48> 8b 3e 48 83 c3
    08 48 83 c6 08 eb bc 48 39 d1 72 9e 48 39 d0 73 RSP: 002b:00007fff8a413210 EFLAGS: 00000283 RAX:
    00007f5e97108990 RBX: 00007f5e97108338 RCX: ffffffff81d3aa45 RDX: ffffffff81d3aa45 RSI: 00007f5e97108340
    RDI: ffffffff81d3aa45 RBP: 00007f5e97107eb8 R08: 00007f5e97108d88 R09: 0000000093c2e8d9 R10:
    0000000000000000 R11: 0000000000000000 R12: 00007f5e97107eb0 R13: 00007f5e97108338 R14: 00007f5e97107ea8
    R15: 0000000000000019 </TASK> Allocated by task 13: kasan_save_stack+0x1e/0x50 mm/kasan/common.c:38
    kasan_set_track mm/kasan/common.c:46 [inline] set_alloc_info mm/kasan/common.c:434 [inline]
    __kasan_slab_alloc+0x90/0xc0 mm/kasan/common.c:467 kasan_slab_alloc include/linux/kasan.h:259 [inline]
    slab_post_alloc_hook mm/slab.h:519 [inline] slab_alloc_node mm/slub.c:3234 [inline] slab_alloc
    mm/slub.c:3242 [inline] kmem_cache_alloc+0x202/0x3a0 mm/slub.c:3247 dst_alloc+0x146/0x1f0
    net/core/dst.c:92 rt_dst_alloc+0x73/0x430 net/ipv4/route.c:1613 ip_route_input_slow+0x1817/0x3a20
    net/ipv4/route.c:234 ---truncated--- (CVE-2021-47103)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47103");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
    "name": "linux-kvm",
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
    "name": [
     "kernel",
     "kernel-rt"
    ],
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
