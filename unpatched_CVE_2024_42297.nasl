#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228716);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42297");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42297");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: f2fs: fix to don't dirty inode for
    readonly filesystem syzbot reports f2fs bug as below: kernel BUG at fs/f2fs/inode.c:933! RIP:
    0010:f2fs_evict_inode+0x1576/0x1590 fs/f2fs/inode.c:933 Call Trace: evict+0x2a4/0x620 fs/inode.c:664
    dispose_list fs/inode.c:697 [inline] evict_inodes+0x5f8/0x690 fs/inode.c:747
    generic_shutdown_super+0x9d/0x2c0 fs/super.c:675 kill_block_super+0x44/0x90 fs/super.c:1667
    kill_f2fs_super+0x303/0x3b0 fs/f2fs/super.c:4894 deactivate_locked_super+0xc1/0x130 fs/super.c:484
    cleanup_mnt+0x426/0x4c0 fs/namespace.c:1256 task_work_run+0x24a/0x300 kernel/task_work.c:180
    ptrace_notify+0x2cd/0x380 kernel/signal.c:2399 ptrace_report_syscall include/linux/ptrace.h:411 [inline]
    ptrace_report_syscall_exit include/linux/ptrace.h:473 [inline] syscall_exit_work kernel/entry/common.c:251
    [inline] syscall_exit_to_user_mode_prepare kernel/entry/common.c:278 [inline]
    __syscall_exit_to_user_mode_work kernel/entry/common.c:283 [inline] syscall_exit_to_user_mode+0x15c/0x280
    kernel/entry/common.c:296 do_syscall_64+0x50/0x110 arch/x86/entry/common.c:88
    entry_SYSCALL_64_after_hwframe+0x63/0x6b The root cause is: - do_sys_open - f2fs_lookup -
    __f2fs_find_entry - f2fs_i_depth_write - f2fs_mark_inode_dirty_sync - f2fs_dirty_inode -
    set_inode_flag(inode, FI_DIRTY_INODE) - umount - kill_f2fs_super - kill_block_super -
    generic_shutdown_super - sync_filesystem : sb is readonly, skip sync_filesystem() - evict_inodes - iput -
    f2fs_evict_inode - f2fs_bug_on(sbi, is_inode_flag_set(inode, FI_DIRTY_INODE)) : trigger kernel panic When
    we try to repair i_current_depth in readonly filesystem, let's skip dirty inode to avoid panic in later
    f2fs_evict_inode(). (CVE-2024-42297)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
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
    "name": "linux-azure-fde",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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
