#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229549);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35991");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35991");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: dmaengine: idxd: Convert spinlock to
    mutex to lock evl workqueue drain_workqueue() cannot be called safely in a spinlocked context due to
    possible task rescheduling. In the multi-task scenario, calling queue_work() while drain_workqueue() will
    lead to a Call Trace as pushing a work on a draining workqueue is not permitted in spinlocked context.
    Call Trace: <TASK> ? __warn+0x7d/0x140 ? __queue_work+0x2b2/0x440 ? report_bug+0x1f8/0x200 ?
    handle_bug+0x3c/0x70 ? exc_invalid_op+0x18/0x70 ? asm_exc_invalid_op+0x1a/0x20 ? __queue_work+0x2b2/0x440
    queue_work_on+0x28/0x30 idxd_misc_thread+0x303/0x5a0 [idxd] ? __schedule+0x369/0xb40 ?
    __pfx_irq_thread_fn+0x10/0x10 ? irq_thread+0xbc/0x1b0 irq_thread_fn+0x21/0x70 irq_thread+0x102/0x1b0 ?
    preempt_count_add+0x74/0xa0 ? __pfx_irq_thread_dtor+0x10/0x10 ? __pfx_irq_thread+0x10/0x10
    kthread+0x103/0x140 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x31/0x50 ? __pfx_kthread+0x10/0x10
    ret_from_fork_asm+0x1b/0x30 </TASK> The current implementation uses a spinlock to protect event log
    workqueue and will lead to the Call Trace due to potential task rescheduling. To address the locking
    issue, convert the spinlock to mutex, allowing the drain_workqueue() to be called in a safe mutex-locked
    context. This change ensures proper synchronization when accessing the event log workqueue, preventing
    potential Call Trace and improving the overall robustness of the code. (CVE-2024-35991)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35991");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/20");
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
