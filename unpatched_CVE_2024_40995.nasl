#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228666);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40995");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40995");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: act_api: fix possible
    infinite loop in tcf_idr_check_alloc() syzbot found hanging tasks waiting on rtnl_lock [1] A reproducer is
    available in the syzbot bug. When a request to add multiple actions with the same index is sent, the
    second request will block forever on the first request. This holds rtnl_lock, and causes tasks to hang.
    Return -EAGAIN to prevent infinite looping, while keeping documented behavior. [1] INFO: task
    kworker/1:0:5088 blocked for more than 143 seconds. Not tainted 6.9.0-rc4-syzkaller-00173-g3cdb45594619 #0
    echo 0 > /proc/sys/kernel/hung_task_timeout_secs disables this message. task:kworker/1:0 state:D
    stack:23744 pid:5088 tgid:5088 ppid:2 flags:0x00004000 Workqueue: events_power_efficient
    reg_check_chans_work Call Trace: <TASK> context_switch kernel/sched/core.c:5409 [inline]
    __schedule+0xf15/0x5d00 kernel/sched/core.c:6746 __schedule_loop kernel/sched/core.c:6823 [inline]
    schedule+0xe7/0x350 kernel/sched/core.c:6838 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6895
    __mutex_lock_common kernel/locking/mutex.c:684 [inline] __mutex_lock+0x5b8/0x9c0
    kernel/locking/mutex.c:752 wiphy_lock include/net/cfg80211.h:5953 [inline] reg_leave_invalid_chans
    net/wireless/reg.c:2466 [inline] reg_check_chans_work+0x10a/0x10e0 net/wireless/reg.c:2481
    (CVE-2024-40995)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40995");

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
