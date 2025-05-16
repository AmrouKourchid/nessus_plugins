#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224298);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47454");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47454");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: powerpc/smp: do not decrement idle
    task preempt count in CPU offline With PREEMPT_COUNT=y, when a CPU is offlined and then onlined again, we
    get: BUG: scheduling while atomic: swapper/1/0/0x00000000 no locks held by swapper/1/0. CPU: 1 PID: 0
    Comm: swapper/1 Not tainted 5.15.0-rc2+ #100 Call Trace: dump_stack_lvl+0xac/0x108
    __schedule_bug+0xac/0xe0 __schedule+0xcf8/0x10d0 schedule_idle+0x3c/0x70 do_idle+0x2d8/0x4a0
    cpu_startup_entry+0x38/0x40 start_secondary+0x2ec/0x3a0 start_secondary_prolog+0x10/0x14 This is because
    powerpc's arch_cpu_idle_dead() decrements the idle task's preempt count, for reasons explained in commit
    a7c2bb8279d2 (powerpc: Re-enable preemption before cpu_die()), specifically start_secondary() expects a
    preempt_count() of 0. However, since commit 2c669ef6979c (powerpc/preempt: Don't touch the idle task's
    preempt_count during hotplug) and commit f1a0a376ca0c (sched/core: Initialize the idle task with
    preemption disabled), that justification no longer holds. The idle task isn't supposed to re-enable
    preemption, so remove the vestigial preempt_enable() from the CPU offline path. Tested with pseries and
    powernv in qemu, and pseries on PowerVM. (CVE-2021-47454)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47454");

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
