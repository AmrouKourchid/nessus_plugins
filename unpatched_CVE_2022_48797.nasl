#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225356);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48797");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48797");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm: don't try to NUMA-migrate COW
    pages that have other uses Oded Gabbay reports that enabling NUMA balancing causes corruption with his
    Gaudi accelerator test load: All the details are in the bug, but the bottom line is that somehow, this
    patch causes corruption when the numa balancing feature is enabled AND we don't use process affinity AND
    we use GUP to pin pages so our accelerator can DMA to/from system memory. Either disabling numa balancing,
    using process affinity to bind to specific numa-node or reverting this patch causes the bug to disappear
    and Oded bisected the issue to commit 09854ba94c6a (mm: do_wp_page() simplification). Now, the NUMA
    balancing shouldn't actually be changing the writability of a page, and as such shouldn't matter for COW.
    But it appears it does. Suspicious. However, regardless of that, the condition for enabling NUMA faults in
    change_pte_range() is nonsensical. It uses page_mapcount(page) to decide if a COW page should be NUMA-
    protected or not, and that makes absolutely no sense. The number of mappings a page has is irrelevant: not
    only does GUP get a reference to a page as in Oded's case, but the other mappings migth be paged out and
    the only reference to them would be in the page count. Since we should never try to NUMA-balance a page
    that we can't move anyway due to other references, just fix the code to use 'page_count()'. Oded confirms
    that that fixes his issue. Now, this does imply that something in NUMA balancing ends up changing page
    protections (other than the obvious one of making the page inaccessible to get the NUMA faulting
    information). Otherwise the COW simplification wouldn't matter - since doing the GUP on the page would
    make sure it's writable. The cause of that permission change would be good to figure out too, since it
    clearly results in spurious COW events - but fixing the nonsensical test that just happened to work before
    is obviously the CorrectThing(tm) to do regardless. (CVE-2022-48797)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48797");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
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
