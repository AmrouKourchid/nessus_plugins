#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225429);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48983");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48983");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: io_uring: Fix a null-ptr-deref in
    io_tctx_exit_cb() Syzkaller reports a NULL deref bug as follows: BUG: KASAN: null-ptr-deref in
    io_tctx_exit_cb+0x53/0xd3 Read of size 4 at addr 0000000000000138 by task file1/1955 CPU: 1 PID: 1955
    Comm: file1 Not tainted 6.1.0-rc7-00103-gef4d3ea40565 #75 Hardware name: QEMU Standard PC (i440FX + PIIX,
    1996), BIOS 1.11.0-2.el7 04/01/2014 Call Trace: <TASK> dump_stack_lvl+0xcd/0x134 ?
    io_tctx_exit_cb+0x53/0xd3 kasan_report+0xbb/0x1f0 ? io_tctx_exit_cb+0x53/0xd3
    kasan_check_range+0x140/0x190 io_tctx_exit_cb+0x53/0xd3 task_work_run+0x164/0x250 ?
    task_work_cancel+0x30/0x30 get_signal+0x1c3/0x2440 ? lock_downgrade+0x6e0/0x6e0 ?
    lock_downgrade+0x6e0/0x6e0 ? exit_signals+0x8b0/0x8b0 ? do_raw_read_unlock+0x3b/0x70 ?
    do_raw_spin_unlock+0x50/0x230 arch_do_signal_or_restart+0x82/0x2470 ? kmem_cache_free+0x260/0x4b0 ?
    putname+0xfe/0x140 ? get_sigframe_size+0x10/0x10 ? do_execveat_common.isra.0+0x226/0x710 ?
    lockdep_hardirqs_on+0x79/0x100 ? putname+0xfe/0x140 ? do_execveat_common.isra.0+0x238/0x710
    exit_to_user_mode_prepare+0x15f/0x250 syscall_exit_to_user_mode+0x19/0x50 do_syscall_64+0x42/0xb0
    entry_SYSCALL_64_after_hwframe+0x63/0xcd RIP: 0023:0x0 Code: Unable to access opcode bytes at
    0xffffffffffffffd6. RSP: 002b:00000000fffb7790 EFLAGS: 00000200 ORIG_RAX: 000000000000000b RAX:
    0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000 RDX: 0000000000000000 RSI: 0000000000000000
    RDI: 0000000000000000 RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000 R10:
    0000000000000000 R11: 0000000000000000 R12: 0000000000000000 R13: 0000000000000000 R14: 0000000000000000
    R15: 0000000000000000 </TASK> Kernel panic - not syncing: panic_on_warn set ... This happens because the
    adding of task_work from io_ring_exit_work() isn't synchronized with canceling all work items from eg
    exec. The execution of the two are ordered in that they are both run by the task itself, but if
    io_tctx_exit_cb() is queued while we're canceling all work items off exec AND gets executed when the task
    exits to userspace rather than in the main loop in io_uring_cancel_generic(), then we can find
    current->io_uring == NULL and hit the above crash. It's safe to add this NULL check here, because the
    execution of the two paths are done by the task itself. [axboe: add code comment and also put an
    explanation in the commit msg] (CVE-2022-48983)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
