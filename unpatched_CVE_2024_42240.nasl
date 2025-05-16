#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228382);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42240");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42240");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: x86/bhi: Avoid warning in #DB handler
    due to BHI mitigation When BHI mitigation is enabled, if SYSENTER is invoked with the TF flag set then
    entry_SYSENTER_compat() uses CLEAR_BRANCH_HISTORY and calls the clear_bhb_loop() before the TF flag is
    cleared. This causes the #DB handler (exc_debug_kernel()) to issue a warning because single-step is used
    outside the entry_SYSENTER_compat() function. To address this issue, entry_SYSENTER_compat() should use
    CLEAR_BRANCH_HISTORY after making sure the TF flag is cleared. The problem can be reproduced with the
    following sequence: $ cat sysenter_step.c int main() { asm(pushf; pop %ax; bts $8,%ax; push %ax; popf;
    sysenter); } $ gcc -o sysenter_step sysenter_step.c $ ./sysenter_step Segmentation fault (core dumped)
    The program is expected to crash, and the #DB handler will issue a warning. Kernel log: WARNING: CPU: 27
    PID: 7000 at arch/x86/kernel/traps.c:1009 exc_debug_kernel+0xd2/0x160 ... RIP:
    0010:exc_debug_kernel+0xd2/0x160 ... Call Trace: <#DB> ? show_regs+0x68/0x80 ? __warn+0x8c/0x140 ?
    exc_debug_kernel+0xd2/0x160 ? report_bug+0x175/0x1a0 ? handle_bug+0x44/0x90 ? exc_invalid_op+0x1c/0x70 ?
    asm_exc_invalid_op+0x1f/0x30 ? exc_debug_kernel+0xd2/0x160 exc_debug+0x43/0x50 asm_exc_debug+0x1e/0x40
    RIP: 0010:clear_bhb_loop+0x0/0xb0 ... </#DB> <TASK> ? entry_SYSENTER_compat_after_hwframe+0x6e/0x8d
    </TASK> [ bp: Massage commit message. ] (CVE-2024-42240)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42240");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-gkeop",
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
  },
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
