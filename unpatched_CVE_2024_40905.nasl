#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229574);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40905");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40905");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipv6: fix possible race in
    __fib6_drop_pcpu_from() syzbot found a race in __fib6_drop_pcpu_from() [1] If compiler reads more than
    once (*ppcpu_rt), second read could read NULL, if another cpu clears the value in rt6_get_pcpu_route().
    Add a READ_ONCE() to prevent this race. Also add rcu_read_lock()/rcu_read_unlock() because we rely on RCU
    protection while dereferencing pcpu_rt. [1] Oops: general protection fault, probably for non-canonical
    address 0xdffffc0000000012: 0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range
    [0x0000000000000090-0x0000000000000097] CPU: 0 PID: 7543 Comm: kworker/u8:17 Not tainted
    6.10.0-rc1-syzkaller-00013-g2bfcfd584ff5 #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 04/02/2024 Workqueue: netns cleanup_net RIP:
    0010:__fib6_drop_pcpu_from.part.0+0x10a/0x370 net/ipv6/ip6_fib.c:984 Code: f8 48 c1 e8 03 80 3c 28 00 0f
    85 16 02 00 00 4d 8b 3f 4d 85 ff 74 31 e8 74 a7 fa f7 49 8d bf 90 00 00 00 48 89 f8 48 c1 e8 03 <80> 3c 28
    00 0f 85 1e 02 00 00 49 8b 87 90 00 00 00 48 8b 0c 24 48 RSP: 0018:ffffc900040df070 EFLAGS: 00010206 RAX:
    0000000000000012 RBX: 0000000000000001 RCX: ffffffff89932e16 RDX: ffff888049dd1e00 RSI: ffffffff89932d7c
    RDI: 0000000000000091 RBP: dffffc0000000000 R08: 0000000000000005 R09: 0000000000000007 R10:
    0000000000000001 R11: 0000000000000006 R12: ffff88807fa080b8 R13: fffffbfff1a9a07d R14: ffffed100ff41022
    R15: 0000000000000001 FS: 0000000000000000(0000) GS:ffff8880b9200000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000001b32c26000 CR3: 000000005d56e000 CR4: 00000000003526f0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> __fib6_drop_pcpu_from net/ipv6/ip6_fib.c:966
    [inline] fib6_drop_pcpu_from net/ipv6/ip6_fib.c:1027 [inline] fib6_purge_rt+0x7f2/0x9f0
    net/ipv6/ip6_fib.c:1038 fib6_del_route net/ipv6/ip6_fib.c:1998 [inline] fib6_del+0xa70/0x17b0
    net/ipv6/ip6_fib.c:2043 fib6_clean_node+0x426/0x5b0 net/ipv6/ip6_fib.c:2205 fib6_walk_continue+0x44f/0x8d0
    net/ipv6/ip6_fib.c:2127 fib6_walk+0x182/0x370 net/ipv6/ip6_fib.c:2175 fib6_clean_tree+0xd7/0x120
    net/ipv6/ip6_fib.c:2255 __fib6_clean_all+0x100/0x2d0 net/ipv6/ip6_fib.c:2271 rt6_sync_down_dev
    net/ipv6/route.c:4906 [inline] rt6_disable_ip+0x7ed/0xa00 net/ipv6/route.c:4911
    addrconf_ifdown.isra.0+0x117/0x1b40 net/ipv6/addrconf.c:3855 addrconf_notify+0x223/0x19e0
    net/ipv6/addrconf.c:3778 notifier_call_chain+0xb9/0x410 kernel/notifier.c:93
    call_netdevice_notifiers_info+0xbe/0x140 net/core/dev.c:1992 call_netdevice_notifiers_extack
    net/core/dev.c:2030 [inline] call_netdevice_notifiers net/core/dev.c:2044 [inline]
    dev_close_many+0x333/0x6a0 net/core/dev.c:1585 unregister_netdevice_many_notify+0x46d/0x19f0
    net/core/dev.c:11193 unregister_netdevice_many net/core/dev.c:11276 [inline]
    default_device_exit_batch+0x85b/0xae0 net/core/dev.c:11759 ops_exit_list+0x128/0x180
    net/core/net_namespace.c:178 cleanup_net+0x5b7/0xbf0 net/core/net_namespace.c:640
    process_one_work+0x9fb/0x1b60 kernel/workqueue.c:3231 process_scheduled_works kernel/workqueue.c:3312
    [inline] worker_thread+0x6c8/0xf70 kernel/workqueue.c:3393 kthread+0x2c1/0x3a0 kernel/kthread.c:389
    ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30
    arch/x86/entry/entry_64.S:244 (CVE-2024-40905)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40905");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
       "match": {
        "os_version": "8"
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
