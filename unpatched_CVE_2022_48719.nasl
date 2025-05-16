#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225340);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48719");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48719");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net, neigh: Do not trigger immediate
    probes on NUD_FAILED from neigh_managed_work syzkaller was able to trigger a deadlock for NTF_MANAGED
    entries [0]: kworker/0:16/14617 is trying to acquire lock: ffffffff8d4dd370 (&tbl->lock){++-.}-{2:2}, at:
    ___neigh_create+0x9e1/0x2990 net/core/neighbour.c:652 [...] but task is already holding lock:
    ffffffff8d4dd370 (&tbl->lock){++-.}-{2:2}, at: neigh_managed_work+0x35/0x250 net/core/neighbour.c:1572 The
    neighbor entry turned to NUD_FAILED state, where __neigh_event_send() triggered an immediate probe as per
    commit cd28ca0a3dd1 (neigh: reduce arp latency) via neigh_probe() given table lock was held. One option
    to fix this situation is to defer the neigh_probe() back to the neigh_timer_handler() similarly as pre
    cd28ca0a3dd1. For the case of NTF_MANAGED, this deferral is acceptable given this only happens on actual
    failure state and regular / expected state is NUD_VALID with the entry already present. The fix adds a
    parameter to __neigh_event_send() in order to communicate whether immediate probe is allowed or
    disallowed. Existing call-sites of neigh_event_send() default as-is to immediate probe. However, the
    neigh_managed_work() disables it via use of neigh_event_send_probe(). [0] <TASK> __dump_stack
    lib/dump_stack.c:88 [inline] dump_stack_lvl+0xcd/0x134 lib/dump_stack.c:106 print_deadlock_bug
    kernel/locking/lockdep.c:2956 [inline] check_deadlock kernel/locking/lockdep.c:2999 [inline]
    validate_chain kernel/locking/lockdep.c:3788 [inline] __lock_acquire.cold+0x149/0x3ab
    kernel/locking/lockdep.c:5027 lock_acquire kernel/locking/lockdep.c:5639 [inline] lock_acquire+0x1ab/0x510
    kernel/locking/lockdep.c:5604 __raw_write_lock_bh include/linux/rwlock_api_smp.h:202 [inline]
    _raw_write_lock_bh+0x2f/0x40 kernel/locking/spinlock.c:334 ___neigh_create+0x9e1/0x2990
    net/core/neighbour.c:652 ip6_finish_output2+0x1070/0x14f0 net/ipv6/ip6_output.c:123 __ip6_finish_output
    net/ipv6/ip6_output.c:191 [inline] __ip6_finish_output+0x61e/0xe90 net/ipv6/ip6_output.c:170
    ip6_finish_output+0x32/0x200 net/ipv6/ip6_output.c:201 NF_HOOK_COND include/linux/netfilter.h:296 [inline]
    ip6_output+0x1e4/0x530 net/ipv6/ip6_output.c:224 dst_output include/net/dst.h:451 [inline] NF_HOOK
    include/linux/netfilter.h:307 [inline] ndisc_send_skb+0xa99/0x17f0 net/ipv6/ndisc.c:508
    ndisc_send_ns+0x3a9/0x840 net/ipv6/ndisc.c:650 ndisc_solicit+0x2cd/0x4f0 net/ipv6/ndisc.c:742
    neigh_probe+0xc2/0x110 net/core/neighbour.c:1040 __neigh_event_send+0x37d/0x1570 net/core/neighbour.c:1201
    neigh_event_send include/net/neighbour.h:470 [inline] neigh_managed_work+0x162/0x250
    net/core/neighbour.c:1574 process_one_work+0x9ac/0x1650 kernel/workqueue.c:2307 worker_thread+0x657/0x1110
    kernel/workqueue.c:2454 kthread+0x2e9/0x3a0 kernel/kthread.c:377 ret_from_fork+0x1f/0x30
    arch/x86/entry/entry_64.S:295 </TASK> (CVE-2022-48719)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/20");
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
