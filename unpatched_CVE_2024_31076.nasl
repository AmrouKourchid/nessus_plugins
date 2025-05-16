#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228168);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-31076");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-31076");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: genirq/cpuhotplug, x86/vector: Prevent
    vector leak during CPU offline The absence of IRQD_MOVE_PCNTXT prevents immediate effectiveness of
    interrupt affinity reconfiguration via procfs. Instead, the change is deferred until the next instance of
    the interrupt being triggered on the original CPU. When the interrupt next triggers on the original CPU,
    the new affinity is enforced within __irq_move_irq(). A vector is allocated from the new CPU, but the old
    vector on the original CPU remains and is not immediately reclaimed. Instead, apicd->move_in_progress is
    flagged, and the reclaiming process is delayed until the next trigger of the interrupt on the new CPU.
    Upon the subsequent triggering of the interrupt on the new CPU, irq_complete_move() adds a task to the old
    CPU's vector_cleanup list if it remains online. Subsequently, the timer on the old CPU iterates over its
    vector_cleanup list, reclaiming old vectors. However, a rare scenario arises if the old CPU is outgoing
    before the interrupt triggers again on the new CPU. In that case irq_force_complete_move() is not invoked
    on the outgoing CPU to reclaim the old apicd->prev_vector because the interrupt isn't currently affine to
    the outgoing CPU, and irq_needs_fixup() returns false. Even though __vector_schedule_cleanup() is later
    called on the new CPU, it doesn't reclaim apicd->prev_vector; instead, it simply resets both
    apicd->move_in_progress and apicd->prev_vector to 0. As a result, the vector remains unreclaimed in
    vector_matrix, leading to a CPU vector leak. To address this issue, move the invocation of
    irq_force_complete_move() before the irq_needs_fixup() call to reclaim apicd->prev_vector, if the
    interrupt is currently or used to be affine to the outgoing CPU. Additionally, reclaim the vector in
    __vector_schedule_cleanup() as well, following a warning message, although theoretically it should never
    see apicd->move_in_progress with apicd->prev_cpu pointing to an offline CPU. (CVE-2024-31076)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-31076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/21");
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
