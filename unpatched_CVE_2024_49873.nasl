#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230958);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-49873");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-49873");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/filemap: fix
    filemap_get_folios_contig THP panic Patch series memfd-pin huge page fixes. Fix multiple bugs that occur
    when using memfd_pin_folios with hugetlb pages and THP. The hugetlb bugs only bite when the page is not
    yet faulted in when memfd_pin_folios is called. The THP bug bites when the starting offset passed to
    memfd_pin_folios is not huge page aligned. See the commit messages for details. This patch (of 5):
    memfd_pin_folios on memory backed by THP panics if the requested start offset is not huge page aligned:
    BUG: kernel NULL pointer dereference, address: 0000000000000036 RIP:
    0010:filemap_get_folios_contig+0xdf/0x290 RSP: 0018:ffffc9002092fbe8 EFLAGS: 00010202 RAX:
    0000000000000002 RBX: 0000000000000002 RCX: 0000000000000002 The fault occurs here, because xas_load
    returns a folio with value 2: filemap_get_folios_contig() for (folio = xas_load(&xas); folio &&
    xas.xa_index <= end; folio = xas_next(&xas)) { ... if (!folio_try_get(folio)) <-- BOOM 2 is an xarray
    sibling entry. We get it because memfd_pin_folios does not round the indices passed to
    filemap_get_folios_contig to huge page boundaries for THP, so we load from the middle of a huge page range
    see a sibling. (It does round for hugetlbfs, at the is_file_hugepages test). To fix, if the folio is a
    sibling, then return the next index as the starting point for the next call to filemap_get_folios_contig.
    (CVE-2024-49873)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
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
        "os_version": "24.04"
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
