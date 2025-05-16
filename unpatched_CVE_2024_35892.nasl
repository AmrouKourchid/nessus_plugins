#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228392);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35892");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35892");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: fix lockdep splat in
    qdisc_tree_reduce_backlog() qdisc_tree_reduce_backlog() is called with the qdisc lock held, not RTNL. We
    must use qdisc_lookup_rcu() instead of qdisc_lookup() syzbot reported: WARNING: suspicious RCU usage
    6.1.74-syzkaller #0 Not tainted ----------------------------- net/sched/sch_api.c:305 suspicious
    rcu_dereference_protected() usage! other info that might help us debug this: rcu_scheduler_active = 2,
    debug_locks = 1 3 locks held by udevd/1142: #0: ffffffff87c729a0 (rcu_read_lock){....}-{1:2}, at:
    rcu_lock_acquire include/linux/rcupdate.h:306 [inline] #0: ffffffff87c729a0 (rcu_read_lock){....}-{1:2},
    at: rcu_read_lock include/linux/rcupdate.h:747 [inline] #0: ffffffff87c729a0 (rcu_read_lock){....}-{1:2},
    at: net_tx_action+0x64a/0x970 net/core/dev.c:5282 #1: ffff888171861108 (&sch->q.lock){+.-.}-{2:2}, at:
    spin_lock include/linux/spinlock.h:350 [inline] #1: ffff888171861108 (&sch->q.lock){+.-.}-{2:2}, at:
    net_tx_action+0x754/0x970 net/core/dev.c:5297 #2: ffffffff87c729a0 (rcu_read_lock){....}-{1:2}, at:
    rcu_lock_acquire include/linux/rcupdate.h:306 [inline] #2: ffffffff87c729a0 (rcu_read_lock){....}-{1:2},
    at: rcu_read_lock include/linux/rcupdate.h:747 [inline] #2: ffffffff87c729a0 (rcu_read_lock){....}-{1:2},
    at: qdisc_tree_reduce_backlog+0x84/0x580 net/sched/sch_api.c:792 stack backtrace: CPU: 1 PID: 1142 Comm:
    udevd Not tainted 6.1.74-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine,
    BIOS Google 01/25/2024 Call Trace: <TASK> [<ffffffff85b85f14>] __dump_stack lib/dump_stack.c:88 [inline]
    [<ffffffff85b85f14>] dump_stack_lvl+0x1b1/0x28f lib/dump_stack.c:106 [<ffffffff85b86007>]
    dump_stack+0x15/0x1e lib/dump_stack.c:113 [<ffffffff81802299>] lockdep_rcu_suspicious+0x1b9/0x260
    kernel/locking/lockdep.c:6592 [<ffffffff84f0054c>] qdisc_lookup+0xac/0x6f0 net/sched/sch_api.c:305
    [<ffffffff84f037c3>] qdisc_tree_reduce_backlog+0x243/0x580 net/sched/sch_api.c:811 [<ffffffff84f5b78c>]
    pfifo_tail_enqueue+0x32c/0x4b0 net/sched/sch_fifo.c:51 [<ffffffff84fbcf63>] qdisc_enqueue
    include/net/sch_generic.h:833 [inline] [<ffffffff84fbcf63>] netem_dequeue+0xeb3/0x15d0
    net/sched/sch_netem.c:723 [<ffffffff84eecab9>] dequeue_skb net/sched/sch_generic.c:292 [inline]
    [<ffffffff84eecab9>] qdisc_restart net/sched/sch_generic.c:397 [inline] [<ffffffff84eecab9>]
    __qdisc_run+0x249/0x1e60 net/sched/sch_generic.c:415 [<ffffffff84d7aa96>] qdisc_run+0xd6/0x260
    include/net/pkt_sched.h:125 [<ffffffff84d85d29>] net_tx_action+0x7c9/0x970 net/core/dev.c:5313
    [<ffffffff85e002bd>] __do_softirq+0x2bd/0x9bd kernel/softirq.c:616 [<ffffffff81568bca>] invoke_softirq
    kernel/softirq.c:447 [inline] [<ffffffff81568bca>] __irq_exit_rcu+0xca/0x230 kernel/softirq.c:700
    [<ffffffff81568ae9>] irq_exit_rcu+0x9/0x20 kernel/softirq.c:712 [<ffffffff85b89f52>]
    sysvec_apic_timer_interrupt+0x42/0x90 arch/x86/kernel/apic/apic.c:1107 [<ffffffff85c00ccb>]
    asm_sysvec_apic_timer_interrupt+0x1b/0x20 arch/x86/include/asm/idtentry.h:656 (CVE-2024-35892)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35892");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/19");
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
