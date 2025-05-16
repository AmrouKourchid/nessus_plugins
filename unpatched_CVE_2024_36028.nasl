#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228664);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36028");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36028");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/hugetlb: fix DEBUG_LOCKS_WARN_ON(1)
    when dissolve_free_hugetlb_folio() When I did memory failure tests recently, below warning occurs:
    DEBUG_LOCKS_WARN_ON(1) WARNING: CPU: 8 PID: 1011 at kernel/locking/lockdep.c:232
    __lock_acquire+0xccb/0x1ca0 Modules linked in: mce_inject hwpoison_inject CPU: 8 PID: 1011 Comm: bash
    Kdump: loaded Not tainted 6.9.0-rc3-next-20240410-00012-gdb69f219f4be #3 Hardware name: QEMU Standard PC
    (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014 RIP:
    0010:__lock_acquire+0xccb/0x1ca0 RSP: 0018:ffffa7a1c7fe3bd0 EFLAGS: 00000082 RAX: 0000000000000000 RBX:
    eb851eb853975fcf RCX: ffffa1ce5fc1c9c8 RDX: 00000000ffffffd8 RSI: 0000000000000027 RDI: ffffa1ce5fc1c9c0
    RBP: ffffa1c6865d3280 R08: ffffffffb0f570a8 R09: 0000000000009ffb R10: 0000000000000286 R11:
    ffffffffb0f2ad50 R12: ffffa1c6865d3d10 R13: ffffa1c6865d3c70 R14: 0000000000000000 R15: 0000000000000004
    FS: 00007ff9f32aa740(0000) GS:ffffa1ce5fc00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 00007ff9f3134ba0 CR3: 00000008484e4000 CR4: 00000000000006f0 Call Trace: <TASK>
    lock_acquire+0xbe/0x2d0 _raw_spin_lock_irqsave+0x3a/0x60 hugepage_subpool_put_pages.part.0+0xe/0xc0
    free_huge_folio+0x253/0x3f0 dissolve_free_huge_page+0x147/0x210 __page_handle_poison+0x9/0x70
    memory_failure+0x4e6/0x8c0 hard_offline_page_store+0x55/0xa0 kernfs_fop_write_iter+0x12c/0x1d0
    vfs_write+0x380/0x540 ksys_write+0x64/0xe0 do_syscall_64+0xbc/0x1d0
    entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7ff9f3114887 RSP: 002b:00007ffecbacb458 EFLAGS:
    00000246 ORIG_RAX: 0000000000000001 RAX: ffffffffffffffda RBX: 000000000000000c RCX: 00007ff9f3114887 RDX:
    000000000000000c RSI: 0000564494164e10 RDI: 0000000000000001 RBP: 0000564494164e10 R08: 00007ff9f31d1460
    R09: 000000007fffffff R10: 0000000000000000 R11: 0000000000000246 R12: 000000000000000c R13:
    00007ff9f321b780 R14: 00007ff9f3217600 R15: 00007ff9f3216a00 </TASK> Kernel panic - not syncing: kernel:
    panic_on_warn set ... CPU: 8 PID: 1011 Comm: bash Kdump: loaded Not tainted
    6.9.0-rc3-next-20240410-00012-gdb69f219f4be #3 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
    rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014 Call Trace: <TASK> panic+0x326/0x350
    check_panic_on_warn+0x4f/0x50 __warn+0x98/0x190 report_bug+0x18e/0x1a0 handle_bug+0x3d/0x70
    exc_invalid_op+0x18/0x70 asm_exc_invalid_op+0x1a/0x20 RIP: 0010:__lock_acquire+0xccb/0x1ca0 RSP:
    0018:ffffa7a1c7fe3bd0 EFLAGS: 00000082 RAX: 0000000000000000 RBX: eb851eb853975fcf RCX: ffffa1ce5fc1c9c8
    RDX: 00000000ffffffd8 RSI: 0000000000000027 RDI: ffffa1ce5fc1c9c0 RBP: ffffa1c6865d3280 R08:
    ffffffffb0f570a8 R09: 0000000000009ffb R10: 0000000000000286 R11: ffffffffb0f2ad50 R12: ffffa1c6865d3d10
    R13: ffffa1c6865d3c70 R14: 0000000000000000 R15: 0000000000000004 lock_acquire+0xbe/0x2d0
    _raw_spin_lock_irqsave+0x3a/0x60 hugepage_subpool_put_pages.part.0+0xe/0xc0 free_huge_folio+0x253/0x3f0
    dissolve_free_huge_page+0x147/0x210 __page_handle_poison+0x9/0x70 memory_failure+0x4e6/0x8c0
    hard_offline_page_store+0x55/0xa0 kernfs_fop_write_iter+0x12c/0x1d0 vfs_write+0x380/0x540
    ksys_write+0x64/0xe0 do_syscall_64+0xbc/0x1d0 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP:
    0033:0x7ff9f3114887 RSP: 002b:00007ffecbacb458 EFLAGS: 00000246 ORIG_RAX: 0000000000000001 RAX:
    ffffffffffffffda RBX: 000000000000000c RCX: 00007ff9f3114887 RDX: 000000000000000c RSI: 0000564494164e10
    RDI: 0000000000000001 RBP: 0000564494164e10 R08: 00007ff9f31d1460 R09: 000000007fffffff R10:
    0000000000000000 R11: 0000000000000246 R12: 000000000000000c R13: 00007ff9f321b780 R14: 00007ff9f3217600
    R15: 00007ff9f3216a00 </TASK> After git bisecting and digging into the code, I believe the root cause is
    that _deferred_list field of folio is unioned with _hugetlb_subpool field. In
    __update_and_free_hugetlb_folio(), folio->_deferred_ ---truncated--- (CVE-2024-36028)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36028");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
