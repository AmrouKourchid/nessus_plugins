#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228778);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36286");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36286");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: nfnetlink_queue: acquire
    rcu_read_lock() in instance_destroy_rcu() syzbot reported that nf_reinject() could be called without
    rcu_read_lock() : WARNING: suspicious RCU usage 6.9.0-rc7-syzkaller-02060-g5c1672705a1a #0 Not tainted
    net/netfilter/nfnetlink_queue.c:263 suspicious rcu_dereference_check() usage! other info that might help
    us debug this: rcu_scheduler_active = 2, debug_locks = 1 2 locks held by syz-executor.4/13427: #0:
    ffffffff8e334f60 (rcu_callback){....}-{0:0}, at: rcu_lock_acquire include/linux/rcupdate.h:329 [inline]
    #0: ffffffff8e334f60 (rcu_callback){....}-{0:0}, at: rcu_do_batch kernel/rcu/tree.c:2190 [inline] #0:
    ffffffff8e334f60 (rcu_callback){....}-{0:0}, at: rcu_core+0xa86/0x1830 kernel/rcu/tree.c:2471 #1:
    ffff88801ca92958 (&inst->lock){+.-.}-{2:2}, at: spin_lock_bh include/linux/spinlock.h:356 [inline] #1:
    ffff88801ca92958 (&inst->lock){+.-.}-{2:2}, at: nfqnl_flush net/netfilter/nfnetlink_queue.c:405 [inline]
    #1: ffff88801ca92958 (&inst->lock){+.-.}-{2:2}, at: instance_destroy_rcu+0x30/0x220
    net/netfilter/nfnetlink_queue.c:172 stack backtrace: CPU: 0 PID: 13427 Comm: syz-executor.4 Not tainted
    6.9.0-rc7-syzkaller-02060-g5c1672705a1a #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 04/02/2024 Call Trace: <IRQ> __dump_stack lib/dump_stack.c:88 [inline]
    dump_stack_lvl+0x241/0x360 lib/dump_stack.c:114 lockdep_rcu_suspicious+0x221/0x340
    kernel/locking/lockdep.c:6712 nf_reinject net/netfilter/nfnetlink_queue.c:323 [inline]
    nfqnl_reinject+0x6ec/0x1120 net/netfilter/nfnetlink_queue.c:397 nfqnl_flush
    net/netfilter/nfnetlink_queue.c:410 [inline] instance_destroy_rcu+0x1ae/0x220
    net/netfilter/nfnetlink_queue.c:172 rcu_do_batch kernel/rcu/tree.c:2196 [inline] rcu_core+0xafd/0x1830
    kernel/rcu/tree.c:2471 handle_softirqs+0x2d6/0x990 kernel/softirq.c:554 __do_softirq kernel/softirq.c:588
    [inline] invoke_softirq kernel/softirq.c:428 [inline] __irq_exit_rcu+0xf4/0x1c0 kernel/softirq.c:637
    irq_exit_rcu+0x9/0x30 kernel/softirq.c:649 instr_sysvec_apic_timer_interrupt
    arch/x86/kernel/apic/apic.c:1043 [inline] sysvec_apic_timer_interrupt+0xa6/0xc0
    arch/x86/kernel/apic/apic.c:1043 </IRQ> <TASK> (CVE-2024-36286)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/21");
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
