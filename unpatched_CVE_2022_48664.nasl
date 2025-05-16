#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225279);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48664");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48664");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: fix hang during unmount when
    stopping a space reclaim worker Often when running generic/562 from fstests we can hang during unmount,
    resulting in a trace like this: Sep 07 11:52:00 debian9 unknown: run fstests generic/562 at 2022-09-07
    11:52:00 Sep 07 11:55:32 debian9 kernel: INFO: task umount:49438 blocked for more than 120 seconds. Sep 07
    11:55:32 debian9 kernel: Not tainted 6.0.0-rc2-btrfs-next-122 #1 Sep 07 11:55:32 debian9 kernel: echo 0 >
    /proc/sys/kernel/hung_task_timeout_secs disables this message. Sep 07 11:55:32 debian9 kernel:
    task:umount state:D stack: 0 pid:49438 ppid: 25683 flags:0x00004000 Sep 07 11:55:32 debian9 kernel: Call
    Trace: Sep 07 11:55:32 debian9 kernel: <TASK> Sep 07 11:55:32 debian9 kernel: __schedule+0x3c8/0xec0 Sep
    07 11:55:32 debian9 kernel: ? rcu_read_lock_sched_held+0x12/0x70 Sep 07 11:55:32 debian9 kernel:
    schedule+0x5d/0xf0 Sep 07 11:55:32 debian9 kernel: schedule_timeout+0xf1/0x130 Sep 07 11:55:32 debian9
    kernel: ? lock_release+0x224/0x4a0 Sep 07 11:55:32 debian9 kernel: ? lock_acquired+0x1a0/0x420 Sep 07
    11:55:32 debian9 kernel: ? trace_hardirqs_on+0x2c/0xd0 Sep 07 11:55:32 debian9 kernel:
    __wait_for_common+0xac/0x200 Sep 07 11:55:32 debian9 kernel: ? usleep_range_state+0xb0/0xb0 Sep 07
    11:55:32 debian9 kernel: __flush_work+0x26d/0x530 Sep 07 11:55:32 debian9 kernel: ?
    flush_workqueue_prep_pwqs+0x140/0x140 Sep 07 11:55:32 debian9 kernel: ? trace_clock_local+0xc/0x30 Sep 07
    11:55:32 debian9 kernel: __cancel_work_timer+0x11f/0x1b0 Sep 07 11:55:32 debian9 kernel: ?
    close_ctree+0x12b/0x5b3 [btrfs] Sep 07 11:55:32 debian9 kernel: ? __trace_bputs+0x10b/0x170 Sep 07
    11:55:32 debian9 kernel: close_ctree+0x152/0x5b3 [btrfs] Sep 07 11:55:32 debian9 kernel: ?
    evict_inodes+0x166/0x1c0 Sep 07 11:55:32 debian9 kernel: generic_shutdown_super+0x71/0x120 Sep 07 11:55:32
    debian9 kernel: kill_anon_super+0x14/0x30 Sep 07 11:55:32 debian9 kernel: btrfs_kill_super+0x12/0x20
    [btrfs] Sep 07 11:55:32 debian9 kernel: deactivate_locked_super+0x2e/0xa0 Sep 07 11:55:32 debian9 kernel:
    cleanup_mnt+0x100/0x160 Sep 07 11:55:32 debian9 kernel: task_work_run+0x59/0xa0 Sep 07 11:55:32 debian9
    kernel: exit_to_user_mode_prepare+0x1a6/0x1b0 Sep 07 11:55:32 debian9 kernel:
    syscall_exit_to_user_mode+0x16/0x40 Sep 07 11:55:32 debian9 kernel: do_syscall_64+0x48/0x90 Sep 07
    11:55:32 debian9 kernel: entry_SYSCALL_64_after_hwframe+0x63/0xcd Sep 07 11:55:32 debian9 kernel: RIP:
    0033:0x7fcde59a57a7 Sep 07 11:55:32 debian9 kernel: RSP: 002b:00007ffe914217c8 EFLAGS: 00000246 ORIG_RAX:
    00000000000000a6 Sep 07 11:55:32 debian9 kernel: RAX: 0000000000000000 RBX: 00007fcde5ae8264 RCX:
    00007fcde59a57a7 Sep 07 11:55:32 debian9 kernel: RDX: 0000000000000000 RSI: 0000000000000000 RDI:
    000055b57556cdd0 Sep 07 11:55:32 debian9 kernel: RBP: 000055b57556cba0 R08: 0000000000000000 R09:
    00007ffe91420570 Sep 07 11:55:32 debian9 kernel: R10: 0000000000000000 R11: 0000000000000246 R12:
    0000000000000000 Sep 07 11:55:32 debian9 kernel: R13: 000055b57556cdd0 R14: 000055b57556ccb8 R15:
    0000000000000000 Sep 07 11:55:32 debian9 kernel: </TASK> What happens is the following: 1) The cleaner
    kthread tries to start a transaction to delete an unused block group, but the metadata reservation can not
    be satisfied right away, so a reservation ticket is created and it starts the async metadata reclaim task
    (fs_info->async_reclaim_work); 2) Writeback for all the filler inodes with an i_size of 2K starts
    (generic/562 creates a lot of 2K files with the goal of filling metadata space). We try to create an
    inline extent for them, but we fail when trying to insert the inline extent with -ENOSPC (at
    cow_file_range_inline()) - since this is not critical, we fallback to non-inline mode (back to
    cow_file_range()), reserve extents ---truncated--- (CVE-2022-48664)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48664");

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
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-5.15",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-ibm",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
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
