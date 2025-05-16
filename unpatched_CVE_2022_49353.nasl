#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225202);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49353");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49353");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: powerpc/papr_scm: don't requests stats
    with '0' sized stats buffer Sachin reported [1] that on a POWER-10 lpar he is seeing a kernel panic being
    reported with vPMEM when papr_scm probe is being called. The panic is of the form below and is observed
    only with following option disabled(profile) for the said LPAR 'Enable Performance Information Collection'
    in the HMC: Kernel attempted to write user page (1c) - exploit attempt? (uid: 0) BUG: Kernel NULL pointer
    dereference on write at 0x0000001c Faulting instruction address: 0xc008000001b90844 Oops: Kernel access of
    bad area, sig: 11 [#1] <snip> NIP [c008000001b90844] drc_pmem_query_stats+0x5c/0x270 [papr_scm] LR
    [c008000001b92794] papr_scm_probe+0x2ac/0x6ec [papr_scm] Call Trace: 0xc00000000941bca0 (unreliable)
    papr_scm_probe+0x2ac/0x6ec [papr_scm] platform_probe+0x98/0x150 really_probe+0xfc/0x510
    __driver_probe_device+0x17c/0x230 <snip> ---[ end trace 0000000000000000 ]--- Kernel panic - not syncing:
    Fatal exception On investigation looks like this panic was caused due to a 'stat_buffer' of size==0 being
    provided to drc_pmem_query_stats() to fetch all performance stats-ids of an NVDIMM. However
    drc_pmem_query_stats() shouldn't have been called since the vPMEM NVDIMM doesn't support and performance
    stat-id's. This was caused due to missing check for 'p->stat_buffer_len' at the beginning of
    papr_scm_pmu_check_events() which indicates that the NVDIMM doesn't support performance-stats. Fix this by
    introducing the check for 'p->stat_buffer_len' at the beginning of papr_scm_pmu_check_events(). [1]
    https://lore.kernel.org/all/6B3A522A-6A5F-4CC9-B268-0C63AA6E07D3@linux.ibm.com (CVE-2022-49353)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
