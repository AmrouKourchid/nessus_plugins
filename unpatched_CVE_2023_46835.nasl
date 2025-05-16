#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226066);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-46835");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-46835");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - The current setup of the quarantine page tables assumes that the quarantine domain (dom_io) has been
    initialized with an address width of DEFAULT_DOMAIN_ADDRESS_WIDTH (48) and hence 4 page table levels.
    However dom_io being a PV domain gets the AMD-Vi IOMMU page tables levels based on the maximum (hot
    pluggable) RAM address, and hence on systems with no RAM above the 512GB mark only 3 page-table levels are
    configured in the IOMMU. On systems without RAM above the 512GB boundary amd_iommu_quarantine_init() will
    setup page tables for the scratch page with 4 levels, while the IOMMU will be configured to use 3 levels
    only, resulting in the last page table directory (PDE) effectively becoming a page table entry (PTE), and
    hence a device in quarantine mode gaining write access to the page destined to be a PDE. Due to this page
    table level mismatch, the sink page the device gets read/write access to is no longer cleared between
    device assignment, possibly leading to data leaks. (CVE-2023-46835)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46835");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
     "libxen-dev",
     "libxencall1",
     "libxendevicemodel1",
     "libxenevtchn1",
     "libxenforeignmemory1",
     "libxengnttab1",
     "libxenhypfs1",
     "libxenmisc4.14",
     "libxenstore3.0",
     "libxentoolcore1",
     "libxentoollog1",
     "xen-doc",
     "xen-hypervisor-4.14-amd64",
     "xen-hypervisor-4.14-arm64",
     "xen-hypervisor-4.14-armhf",
     "xen-hypervisor-common",
     "xen-system-amd64",
     "xen-system-arm64",
     "xen-system-armhf",
     "xen-utils-4.14",
     "xen-utils-common",
     "xenstore-utils"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
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
