#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229224);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-39483");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-39483");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: SVM: WARN on vNMI + NMI window
    iff NMIs are outright masked When requesting an NMI window, WARN on vNMI support being enabled if and only
    if NMIs are actually masked, i.e. if the vCPU is already handling an NMI. KVM's ABI for NMIs that arrive
    simultanesouly (from KVM's point of view) is to inject one NMI and pend the other. When using vNMI, KVM
    pends the second NMI simply by setting V_NMI_PENDING, and lets the CPU do the rest (hardware automatically
    sets V_NMI_BLOCKING when an NMI is injected). However, if KVM can't immediately inject an NMI, e.g.
    because the vCPU is in an STI shadow or is running with GIF=0, then KVM will request an NMI window and
    trigger the WARN (but still function correctly). Whether or not the GIF=0 case makes sense is debatable,
    as the intent of KVM's behavior is to provide functionality that is as close to real hardware as possible.
    E.g. if two NMIs are sent in quick succession, the probability of both NMIs arriving in an STI shadow is
    infinitesimally low on real hardware, but significantly larger in a virtual environment, e.g. if the vCPU
    is preempted in the STI shadow. For GIF=0, the argument isn't as clear cut, because the window where two
    NMIs can collide is much larger in bare metal (though still small). That said, KVM should not have
    divergent behavior for the GIF=0 case based on whether or not vNMI support is enabled. And KVM has allowed
    simultaneous NMIs with GIF=0 for over a decade, since commit 7460fb4a3400 (KVM: Fix simultaneous NMIs).
    I.e. KVM's GIF=0 handling shouldn't be modified without a *really* good reason to do so, and if KVM's
    behavior were to be modified, it should be done irrespective of vNMI support. (CVE-2024-39483)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39483");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/05");
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
