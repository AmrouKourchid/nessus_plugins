#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228740);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36979");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36979");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: bridge: mst: fix vlan use-after-
    free syzbot reported a suspicious rcu usage[1] in bridge's mst code. While fixing it I noticed that
    nothing prevents a vlan to be freed while walking the list from the same path (br forward delay timer).
    Fix the rcu usage and also make sure we are not accessing freed memory by making br_mst_vlan_set_state use
    rcu read lock. [1] WARNING: suspicious RCU usage 6.9.0-rc6-syzkaller #0 Not tainted
    ----------------------------- net/bridge/br_private.h:1599 suspicious rcu_dereference_protected() usage!
    ... stack backtrace: CPU: 1 PID: 8017 Comm: syz-executor.1 Not tainted 6.9.0-rc6-syzkaller #0 Hardware
    name: Google Google Compute Engine/Google Compute Engine, BIOS Google 03/27/2024 Call Trace: <IRQ>
    __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:114
    lockdep_rcu_suspicious+0x221/0x340 kernel/locking/lockdep.c:6712 nbp_vlan_group
    net/bridge/br_private.h:1599 [inline] br_mst_set_state+0x1ea/0x650 net/bridge/br_mst.c:105
    br_set_state+0x28a/0x7b0 net/bridge/br_stp.c:47 br_forward_delay_timer_expired+0x176/0x440
    net/bridge/br_stp_timer.c:88 call_timer_fn+0x18e/0x650 kernel/time/timer.c:1793 expire_timers
    kernel/time/timer.c:1844 [inline] __run_timers kernel/time/timer.c:2418 [inline]
    __run_timer_base+0x66a/0x8e0 kernel/time/timer.c:2429 run_timer_base kernel/time/timer.c:2438 [inline]
    run_timer_softirq+0xb7/0x170 kernel/time/timer.c:2448 __do_softirq+0x2c6/0x980 kernel/softirq.c:554
    invoke_softirq kernel/softirq.c:428 [inline] __irq_exit_rcu+0xf2/0x1c0 kernel/softirq.c:633
    irq_exit_rcu+0x9/0x30 kernel/softirq.c:645 instr_sysvec_apic_timer_interrupt
    arch/x86/kernel/apic/apic.c:1043 [inline] sysvec_apic_timer_interrupt+0xa6/0xc0
    arch/x86/kernel/apic/apic.c:1043 </IRQ> <TASK> asm_sysvec_apic_timer_interrupt+0x1a/0x20
    arch/x86/include/asm/idtentry.h:702 RIP: 0010:lock_acquire+0x264/0x550 kernel/locking/lockdep.c:5758 Code:
    2b 00 74 08 4c 89 f7 e8 ba d1 84 00 f6 44 24 61 02 0f 85 85 01 00 00 41 f7 c7 00 02 00 00 74 01 fb 48 c7
    44 24 40 0e 36 e0 45 <4b> c7 44 25 00 00 00 00 00 43 c7 44 25 09 00 00 00 00 43 c7 44 25 RSP:
    0018:ffffc90013657100 EFLAGS: 00000206 RAX: 0000000000000001 RBX: 1ffff920026cae2c RCX: 0000000000000001
    RDX: dffffc0000000000 RSI: ffffffff8bcaca00 RDI: ffffffff8c1eaa60 RBP: ffffc90013657260 R08:
    ffffffff92efe507 R09: 1ffffffff25dfca0 R10: dffffc0000000000 R11: fffffbfff25dfca1 R12: 1ffff920026cae28
    R13: dffffc0000000000 R14: ffffc90013657160 R15: 0000000000000246 (CVE-2024-36979)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
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
