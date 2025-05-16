#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229477);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-44975");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-44975");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: cgroup/cpuset: fix panic caused by
    partcmd_update We find a bug as below: BUG: unable to handle page fault for address: 00000003 PGD 0 P4D 0
    Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 3 PID: 358 Comm: bash Tainted: G W I 6.6.0-10893-g60d6 Hardware
    name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/4 RIP:
    0010:partition_sched_domains_locked+0x483/0x600 Code: 01 48 85 d2 74 0d 48 83 05 29 3f f8 03 01 f3 48 0f
    bc c2 89 c0 48 9 RSP: 0018:ffffc90000fdbc58 EFLAGS: 00000202 RAX: 0000000100000003 RBX: ffff888100b3dfa0
    RCX: 0000000000000000 RDX: 0000000000000000 RSI: 0000000000000000 RDI: 000000000002fe80 RBP:
    ffff888100b3dfb0 R08: 0000000000000001 R09: 0000000000000000 R10: ffffc90000fdbcb0 R11: 0000000000000004
    R12: 0000000000000002 R13: ffff888100a92b48 R14: 0000000000000000 R15: 0000000000000000 FS:
    00007f44a5425740(0000) GS:ffff888237d80000(0000) knlGS:0000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 0000000100030973 CR3: 000000010722c000 CR4: 00000000000006e0 Call Trace: <TASK> ?
    show_regs+0x8c/0xa0 ? __die_body+0x23/0xa0 ? __die+0x3a/0x50 ? page_fault_oops+0x1d2/0x5c0 ?
    partition_sched_domains_locked+0x483/0x600 ? search_module_extables+0x2a/0xb0 ?
    search_exception_tables+0x67/0x90 ? kernelmode_fixup_or_oops+0x144/0x1b0 ?
    __bad_area_nosemaphore+0x211/0x360 ? up_read+0x3b/0x50 ? bad_area_nosemaphore+0x1a/0x30 ?
    exc_page_fault+0x890/0xd90 ? __lock_acquire.constprop.0+0x24f/0x8d0 ?
    __lock_acquire.constprop.0+0x24f/0x8d0 ? asm_exc_page_fault+0x26/0x30 ?
    partition_sched_domains_locked+0x483/0x600 ? partition_sched_domains_locked+0xf0/0x600
    rebuild_sched_domains_locked+0x806/0xdc0 update_partition_sd_lb+0x118/0x130
    cpuset_write_resmask+0xffc/0x1420 cgroup_file_write+0xb2/0x290 kernfs_fop_write_iter+0x194/0x290
    new_sync_write+0xeb/0x160 vfs_write+0x16f/0x1d0 ksys_write+0x81/0x180 __x64_sys_write+0x21/0x30
    x64_sys_call+0x2f25/0x4630 do_syscall_64+0x44/0xb0 entry_SYSCALL_64_after_hwframe+0x78/0xe2 RIP:
    0033:0x7f44a553c887 It can be reproduced with cammands: cd /sys/fs/cgroup/ mkdir test cd test/ echo
    +cpuset > ../cgroup.subtree_control echo root > cpuset.cpus.partition cat
    /sys/fs/cgroup/cpuset.cpus.effective 0-3 echo 0-3 > cpuset.cpus // taking away all cpus from root This
    issue is caused by the incorrect rebuilding of scheduling domains. In this scenario,
    test/cpuset.cpus.partition should be an invalid root and should not trigger the rebuilding of scheduling
    domains. When calling update_parent_effective_cpumask with partcmd_update, if newmask is not null, it
    should recheck newmask whether there are cpus is available for parect/cs that has tasks. (CVE-2024-44975)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
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
