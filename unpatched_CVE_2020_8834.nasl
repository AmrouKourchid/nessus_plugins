#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(223612);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_cve_id("CVE-2020-8834");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2020-8834");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - KVM in the Linux kernel on Power8 processors has a conflicting use of HSTATE_HOST_R1 to store r1 state in
    kvmppc_hv_entry plus in kvmppc_{save,restore}_tm, leading to a stack corruption. Because of this, an
    attacker with the ability run code in kernel space of a guest VM can cause the host kernel to panic. There
    were two commits that, according to the reporter, introduced the vulnerability: f024ee098476 (KVM: PPC:
    Book3S HV: Pull out TM state save/restore into separate procedures) 87a11bb6a7f7 (KVM: PPC: Book3S HV:
    Work around XER[SO] bug in fake suspend mode) The former landed in 4.8, the latter in 4.17. This was
    fixed without realizing the impact in 4.18 with the following three commits, though it's believed the
    first is the only strictly necessary commit: 6f597c6b63b6 (KVM: PPC: Book3S PR: Add guest MSR parameter
    for kvmppc_save_tm()/kvmppc_restore_tm()) 7b0e827c6970 (KVM: PPC: Book3S HV: Factor fake-suspend
    handling out of kvmppc_save/restore_tm) 009c872a8bc4 (KVM: PPC: Book3S PR: Move
    kvmppc_save_tm/kvmppc_restore_tm to separate file) (CVE-2020-8834)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8834");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

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
    "name": "kernel",
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
        "os_version": "7"
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
