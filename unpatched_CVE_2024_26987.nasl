#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227488);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26987");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26987");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/memory-failure: fix deadlock when
    hugetlb_optimize_vmemmap is enabled When I did hard offline test with hugetlb pages, below deadlock
    occurs: ====================================================== WARNING: possible circular locking
    dependency detected 6.8.0-11409-gf6cef5f8c37f #1 Not tainted
    ------------------------------------------------------ bash/46904 is trying to acquire lock:
    ffffffffabe68910 (cpu_hotplug_lock){++++}-{0:0}, at: static_key_slow_dec+0x16/0x60 but task is already
    holding lock: ffffffffabf92ea8 (pcp_batch_high_lock){+.+.}-{3:3}, at: zone_pcp_disable+0x16/0x40 which
    lock already depends on the new lock. the existing dependency chain (in reverse order) is: -> #1
    (pcp_batch_high_lock){+.+.}-{3:3}: __mutex_lock+0x6c/0x770 page_alloc_cpu_online+0x3c/0x70
    cpuhp_invoke_callback+0x397/0x5f0 __cpuhp_invoke_callback_range+0x71/0xe0 _cpu_up+0xeb/0x210
    cpu_up+0x91/0xe0 cpuhp_bringup_mask+0x49/0xb0 bringup_nonboot_cpus+0xb7/0xe0 smp_init+0x25/0xa0
    kernel_init_freeable+0x15f/0x3e0 kernel_init+0x15/0x1b0 ret_from_fork+0x2f/0x50
    ret_from_fork_asm+0x1a/0x30 -> #0 (cpu_hotplug_lock){++++}-{0:0}: __lock_acquire+0x1298/0x1cd0
    lock_acquire+0xc0/0x2b0 cpus_read_lock+0x2a/0xc0 static_key_slow_dec+0x16/0x60
    __hugetlb_vmemmap_restore_folio+0x1b9/0x200 dissolve_free_huge_page+0x211/0x260
    __page_handle_poison+0x45/0xc0 memory_failure+0x65e/0xc70 hard_offline_page_store+0x55/0xa0
    kernfs_fop_write_iter+0x12c/0x1d0 vfs_write+0x387/0x550 ksys_write+0x64/0xe0 do_syscall_64+0xca/0x1e0
    entry_SYSCALL_64_after_hwframe+0x6d/0x75 other info that might help us debug this: Possible unsafe locking
    scenario: CPU0 CPU1 ---- ---- lock(pcp_batch_high_lock); lock(cpu_hotplug_lock);
    lock(pcp_batch_high_lock); rlock(cpu_hotplug_lock); *** DEADLOCK *** 5 locks held by bash/46904: #0:
    ffff98f6c3bb23f0 (sb_writers#5){.+.+}-{0:0}, at: ksys_write+0x64/0xe0 #1: ffff98f6c328e488
    (&of->mutex){+.+.}-{3:3}, at: kernfs_fop_write_iter+0xf8/0x1d0 #2: ffff98ef83b31890
    (kn->active#113){.+.+}-{0:0}, at: kernfs_fop_write_iter+0x100/0x1d0 #3: ffffffffabf9db48
    (mf_mutex){+.+.}-{3:3}, at: memory_failure+0x44/0xc70 #4: ffffffffabf92ea8
    (pcp_batch_high_lock){+.+.}-{3:3}, at: zone_pcp_disable+0x16/0x40 stack backtrace: CPU: 10 PID: 46904
    Comm: bash Kdump: loaded Not tainted 6.8.0-11409-gf6cef5f8c37f #1 Hardware name: QEMU Standard PC (i440FX
    + PIIX, 1996), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014 Call Trace: <TASK>
    dump_stack_lvl+0x68/0xa0 check_noncircular+0x129/0x140 __lock_acquire+0x1298/0x1cd0
    lock_acquire+0xc0/0x2b0 cpus_read_lock+0x2a/0xc0 static_key_slow_dec+0x16/0x60
    __hugetlb_vmemmap_restore_folio+0x1b9/0x200 dissolve_free_huge_page+0x211/0x260
    __page_handle_poison+0x45/0xc0 memory_failure+0x65e/0xc70 hard_offline_page_store+0x55/0xa0
    kernfs_fop_write_iter+0x12c/0x1d0 vfs_write+0x387/0x550 ksys_write+0x64/0xe0 do_syscall_64+0xca/0x1e0
    entry_SYSCALL_64_after_hwframe+0x6d/0x75 RIP: 0033:0x7fc862314887 Code: 10 00 f7 d8 64 89 02 48 c7 c0 ff
    ff ff ff eb b7 0f 1f 00 f3 0f 1e fa 64 8b 04 25 18 00 00 00 85 c0 75 10 b8 01 00 00 00 0f 05 <48> 3d 00 f0
    ff ff 77 51 c3 48 83 ec 28 48 89 54 24 18 48 89 74 24 RSP: 002b:00007fff19311268 EFLAGS: 00000246
    ORIG_RAX: 0000000000000001 RAX: ffffffffffffffda RBX: 000000000000000c RCX: 00007fc862314887 RDX:
    000000000000000c RSI: 000056405645fe10 RDI: 0000000000000001 RBP: 000056405645fe10 R08: 00007fc8623d1460
    R09: 000000007fffffff R10: 0000000000000000 R11: 0000000000000246 R12: 000000000000000c R13:
    00007fc86241b780 R14: 00007fc862417600 R15: 00007fc862416a00 In short, below scene breaks the
    ---truncated--- (CVE-2024-26987)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26987");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/27");
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
