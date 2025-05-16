#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228208);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26880");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26880");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: dm: call the resume method on internal
    suspend There is this reported crash when experimenting with the lvm2 testsuite. The list corruption is
    caused by the fact that the postsuspend and resume methods were not paired correctly; there were two
    consecutive calls to the origin_postsuspend function. The second call attempts to remove the hash_list
    entry from a list, while it was already removed by the first call. Fix __dm_internal_resume so that it
    calls the preresume and resume methods of the table's targets. If a preresume method of some target fails,
    we are in a tricky situation. We can't return an error because dm_internal_resume isn't supposed to return
    errors. We can't return success, because then the resume and postsuspend methods would not be paired
    correctly. So, we set the DMF_SUSPENDED flag and we fake normal suspend - it may confuse userspace tools,
    but it won't cause a kernel crash. ------------[ cut here ]------------ kernel BUG at lib/list_debug.c:56!
    invalid opcode: 0000 [#1] PREEMPT SMP CPU: 1 PID: 8343 Comm: dmsetup Not tainted 6.8.0-rc6 #4 Hardware
    name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014 RIP:
    0010:__list_del_entry_valid_or_report+0x77/0xc0 <snip> RSP: 0018:ffff8881b831bcc0 EFLAGS: 00010282 RAX:
    000000000000004e RBX: ffff888143b6eb80 RCX: 0000000000000000 RDX: 0000000000000001 RSI: ffffffff819053d0
    RDI: 00000000ffffffff RBP: ffff8881b83a3400 R08: 00000000fffeffff R09: 0000000000000058 R10:
    0000000000000000 R11: ffffffff81a24080 R12: 0000000000000001 R13: ffff88814538e000 R14: ffff888143bc6dc0
    R15: ffffffffa02e4bb0 FS: 00000000f7c0f780(0000) GS:ffff8893f0a40000(0000) knlGS:0000000000000000 CS: 0010
    DS: 002b ES: 002b CR0: 0000000080050033 CR2: 0000000057fb5000 CR3: 0000000143474000 CR4: 00000000000006b0
    Call Trace: <TASK> ? die+0x2d/0x80 ? do_trap+0xeb/0xf0 ? __list_del_entry_valid_or_report+0x77/0xc0 ?
    do_error_trap+0x60/0x80 ? __list_del_entry_valid_or_report+0x77/0xc0 ? exc_invalid_op+0x49/0x60 ?
    __list_del_entry_valid_or_report+0x77/0xc0 ? asm_exc_invalid_op+0x16/0x20 ? table_deps+0x1b0/0x1b0
    [dm_mod] ? __list_del_entry_valid_or_report+0x77/0xc0 origin_postsuspend+0x1a/0x50 [dm_snapshot]
    dm_table_postsuspend_targets+0x34/0x50 [dm_mod] dm_suspend+0xd8/0xf0 [dm_mod] dev_suspend+0x1f2/0x2f0
    [dm_mod] ? table_deps+0x1b0/0x1b0 [dm_mod] ctl_ioctl+0x300/0x5f0 [dm_mod] dm_compat_ctl_ioctl+0x7/0x10
    [dm_mod] __x64_compat_sys_ioctl+0x104/0x170 do_syscall_64+0x184/0x1b0
    entry_SYSCALL_64_after_hwframe+0x46/0x4e RIP: 0033:0xf7e6aead <snip> ---[ end trace 0000000000000000 ]---
    (CVE-2024-26880)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26880");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
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
