#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224399);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47089");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47089");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: kfence: fix memory leak when cat
    kfence objects Hulk robot reported a kmemleak problem: unreferenced object 0xffff93d1d8cc02e8 (size 248):
    comm cat, pid 23327, jiffies 4624670141 (age 495992.217s) hex dump (first 32 bytes): 00 40 85 19 d4 93
    ff ff 00 10 00 00 00 00 00 00 .@.............. 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    ................ backtrace: seq_open+0x2a/0x80 full_proxy_open+0x167/0x1e0 do_dentry_open+0x1e1/0x3a0
    path_openat+0x961/0xa20 do_filp_open+0xae/0x120 do_sys_openat2+0x216/0x2f0 do_sys_open+0x57/0x80
    do_syscall_64+0x33/0x40 entry_SYSCALL_64_after_hwframe+0x44/0xa9 unreferenced object 0xffff93d419854000
    (size 4096): comm cat, pid 23327, jiffies 4624670141 (age 495992.217s) hex dump (first 32 bytes): 6b 66
    65 6e 63 65 2d 23 32 35 30 3a 20 30 78 30 kfence-#250: 0x0 30 30 30 30 30 30 30 37 35 34 62 64 61 31 32 2d
    0000000754bda12- backtrace: seq_read_iter+0x313/0x440 seq_read+0x14b/0x1a0 full_proxy_read+0x56/0x80
    vfs_read+0xa5/0x1b0 ksys_read+0xa0/0xf0 do_syscall_64+0x33/0x40 entry_SYSCALL_64_after_hwframe+0x44/0xa9 I
    find that we can easily reproduce this problem with the following commands: cat
    /sys/kernel/debug/kfence/objects echo scan > /sys/kernel/debug/kmemleak cat /sys/kernel/debug/kmemleak The
    leaked memory is allocated in the stack below: do_syscall_64 do_sys_open do_dentry_open full_proxy_open
    seq_open ---> alloc seq_file vfs_read full_proxy_read seq_read seq_read_iter traverse ---> alloc seq_buf
    And it should have been released in the following process: do_syscall_64 syscall_exit_to_user_mode
    exit_to_user_mode_prepare task_work_run ____fput __fput full_proxy_release ---> free here However, the
    release function corresponding to file_operations is not implemented in kfence. As a result, a memory leak
    occurs. Therefore, the solution to this problem is to implement the corresponding release function.
    (CVE-2021-47089)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/04");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
