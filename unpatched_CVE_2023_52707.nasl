#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226915);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52707");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52707");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: sched/psi: Fix use-after-free in
    ep_remove_wait_queue() If a non-root cgroup gets removed when there is a thread that registered trigger
    and is polling on a pressure file within the cgroup, the polling waitqueue gets freed in the following
    path: do_rmdir cgroup_rmdir kernfs_drain_open_files cgroup_file_release cgroup_pressure_release
    psi_trigger_destroy However, the polling thread still has a reference to the pressure file and will access
    the freed waitqueue when the file is closed or upon exit: fput ep_eventpoll_release ep_free
    ep_remove_wait_queue remove_wait_queue This results in use-after-free as pasted below. The fundamental
    problem here is that cgroup_file_release() (and consequently waitqueue's lifetime) is not tied to the
    file's real lifetime. Using wake_up_pollfree() here might be less than ideal, but it is in line with the
    comment at commit 42288cb44c4b (wait: add wake_up_pollfree()) since the waitqueue's lifetime is not tied
    to file's one and can be considered as another special case. While this would be fixable by somehow making
    cgroup_file_release() be tied to the fput(), it would require sizable refactoring at cgroups or higher
    layer which might be more justifiable if we identify more cases like this. BUG: KASAN: use-after-free in
    _raw_spin_lock_irqsave+0x60/0xc0 Write of size 4 at addr ffff88810e625328 by task a.out/4404 CPU: 19 PID:
    4404 Comm: a.out Not tainted 6.2.0-rc6 #38 Hardware name: Amazon EC2 c5a.8xlarge/, BIOS 1.0 10/16/2017
    Call Trace: <TASK> dump_stack_lvl+0x73/0xa0 print_report+0x16c/0x4e0 kasan_report+0xc3/0xf0
    kasan_check_range+0x2d2/0x310 _raw_spin_lock_irqsave+0x60/0xc0 remove_wait_queue+0x1a/0xa0
    ep_free+0x12c/0x170 ep_eventpoll_release+0x26/0x30 __fput+0x202/0x400 task_work_run+0x11d/0x170
    do_exit+0x495/0x1130 do_group_exit+0x100/0x100 get_signal+0xd67/0xde0 arch_do_signal_or_restart+0x2a/0x2b0
    exit_to_user_mode_prepare+0x94/0x100 syscall_exit_to_user_mode+0x20/0x40 do_syscall_64+0x52/0x90
    entry_SYSCALL_64_after_hwframe+0x63/0xcd </TASK> Allocated by task 4404: kasan_set_track+0x3d/0x60
    __kasan_kmalloc+0x85/0x90 psi_trigger_create+0x113/0x3e0 pressure_write+0x146/0x2e0
    cgroup_file_write+0x11c/0x250 kernfs_fop_write_iter+0x186/0x220 vfs_write+0x3d8/0x5c0
    ksys_write+0x90/0x110 do_syscall_64+0x43/0x90 entry_SYSCALL_64_after_hwframe+0x63/0xcd Freed by task 4407:
    kasan_set_track+0x3d/0x60 kasan_save_free_info+0x27/0x40 ____kasan_slab_free+0x11d/0x170
    slab_free_freelist_hook+0x87/0x150 __kmem_cache_free+0xcb/0x180 psi_trigger_destroy+0x2e8/0x310
    cgroup_file_release+0x4f/0xb0 kernfs_drain_open_files+0x165/0x1f0 kernfs_drain+0x162/0x1a0
    __kernfs_remove+0x1fb/0x310 kernfs_remove_by_name_ns+0x95/0xe0 cgroup_addrm_files+0x67f/0x700
    cgroup_destroy_locked+0x283/0x3c0 cgroup_rmdir+0x29/0x100 kernfs_iop_rmdir+0xd1/0x140 vfs_rmdir+0xfe/0x240
    do_rmdir+0x13d/0x280 __x64_sys_rmdir+0x2c/0x30 do_syscall_64+0x43/0x90
    entry_SYSCALL_64_after_hwframe+0x63/0xcd (CVE-2023-52707)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
