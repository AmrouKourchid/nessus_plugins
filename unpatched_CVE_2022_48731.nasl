#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225552);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48731");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48731");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/kmemleak: avoid scanning potential
    huge holes When using devm_request_free_mem_region() and devm_memremap_pages() to add ZONE_DEVICE memory,
    if requested free mem region's end pfn were huge(e.g., 0x400000000), the node_end_pfn() will be also huge
    (see move_pfn_range_to_zone()). Thus it creates a huge hole between node_start_pfn() and node_end_pfn().
    We found on some AMD APUs, amdkfd requested such a free mem region and created a huge hole. In such a
    case, following code snippet was just doing busy test_bit() looping on the huge hole. for (pfn =
    start_pfn; pfn < end_pfn; pfn++) { struct page *page = pfn_to_online_page(pfn); if (!page) continue; ... }
    So we got a soft lockup: watchdog: BUG: soft lockup - CPU#6 stuck for 26s! [bash:1221] CPU: 6 PID: 1221
    Comm: bash Not tainted 5.15.0-custom #1 RIP: 0010:pfn_to_online_page+0x5/0xd0 Call Trace: ?
    kmemleak_scan+0x16a/0x440 kmemleak_write+0x306/0x3a0 ? common_file_perm+0x72/0x170
    full_proxy_write+0x5c/0x90 vfs_write+0xb9/0x260 ksys_write+0x67/0xe0 __x64_sys_write+0x1a/0x20
    do_syscall_64+0x3b/0xc0 entry_SYSCALL_64_after_hwframe+0x44/0xae I did some tests with the patch. (1)
    amdgpu module unloaded before the patch: real 0m0.976s user 0m0.000s sys 0m0.968s after the patch: real
    0m0.981s user 0m0.000s sys 0m0.973s (2) amdgpu module loaded before the patch: real 0m35.365s user
    0m0.000s sys 0m35.354s after the patch: real 0m1.049s user 0m0.000s sys 0m1.042s (CVE-2022-48731)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48731");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/20");
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
