#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228644);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35989");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35989");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: dmaengine: idxd: Fix oops during rmmod
    on single-CPU platforms During the removal of the idxd driver, registered offline callback is invoked as
    part of the clean up process. However, on systems with only one CPU online, no valid target is available
    to migrate the perf context, resulting in a kernel oops: BUG: unable to handle page fault for address:
    000000000002a2b8 #PF: supervisor write access in kernel mode #PF: error_code(0x0002) - not-present page
    PGD 1470e1067 P4D 0 Oops: 0002 [#1] PREEMPT SMP NOPTI CPU: 0 PID: 20 Comm: cpuhp/0 Not tainted
    6.8.0-rc6-dsa+ #57 Hardware name: Intel Corporation AvenueCity/AvenueCity, BIOS
    BHSDCRB1.86B.2492.D03.2307181620 07/18/2023 RIP: 0010:mutex_lock+0x2e/0x50 ... Call Trace: <TASK>
    __die+0x24/0x70 page_fault_oops+0x82/0x160 do_user_addr_fault+0x65/0x6b0
    __pfx___rdmsr_safe_on_cpu+0x10/0x10 exc_page_fault+0x7d/0x170 asm_exc_page_fault+0x26/0x30
    mutex_lock+0x2e/0x50 mutex_lock+0x1e/0x50 perf_pmu_migrate_context+0x87/0x1f0
    perf_event_cpu_offline+0x76/0x90 [idxd] cpuhp_invoke_callback+0xa2/0x4f0
    __pfx_perf_event_cpu_offline+0x10/0x10 [idxd] cpuhp_thread_fun+0x98/0x150 smpboot_thread_fn+0x27/0x260
    smpboot_thread_fn+0x1af/0x260 __pfx_smpboot_thread_fn+0x10/0x10 kthread+0x103/0x140
    __pfx_kthread+0x10/0x10 ret_from_fork+0x31/0x50 __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 <TASK>
    Fix the issue by preventing the migration of the perf context to an invalid target. (CVE-2024-35989)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35989");

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
