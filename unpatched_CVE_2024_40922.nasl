#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229321);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40922");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40922");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: io_uring/rsrc: don't lock while
    !TASK_RUNNING There is a report of io_rsrc_ref_quiesce() locking a mutex while not TASK_RUNNING, which is
    due to forgetting restoring the state back after io_run_task_work_sig() and attempts to break out of the
    waiting loop. do not call blocking ops when !TASK_RUNNING; state=1 set at [<ffffffff815d2494>]
    prepare_to_wait+0xa4/0x380 kernel/sched/wait.c:237 WARNING: CPU: 2 PID: 397056 at
    kernel/sched/core.c:10099 __might_sleep+0x114/0x160 kernel/sched/core.c:10099 RIP:
    0010:__might_sleep+0x114/0x160 kernel/sched/core.c:10099 Call Trace: <TASK> __mutex_lock_common
    kernel/locking/mutex.c:585 [inline] __mutex_lock+0xb4/0x940 kernel/locking/mutex.c:752
    io_rsrc_ref_quiesce+0x590/0x940 io_uring/rsrc.c:253 io_sqe_buffers_unregister+0xa2/0x340
    io_uring/rsrc.c:799 __io_uring_register io_uring/register.c:424 [inline]
    __do_sys_io_uring_register+0x5b9/0x2400 io_uring/register.c:613 do_syscall_x64 arch/x86/entry/common.c:52
    [inline] do_syscall_64+0xd8/0x270 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x6f/0x77
    (CVE-2024-40922)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40922");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
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
