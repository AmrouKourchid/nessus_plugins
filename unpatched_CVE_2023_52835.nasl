#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226313);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52835");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52835");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: perf/core: Bail out early if the
    request AUX area is out of bound When perf-record with a large AUX area, e.g 4GB, it fails with: #perf
    record -C 0 -m ,4G -e arm_spe_0// -- sleep 1 failed to mmap with 12 (Cannot allocate memory) and it
    reveals a WARNING with __alloc_pages(): ------------[ cut here ]------------ WARNING: CPU: 44 PID: 17573
    at mm/page_alloc.c:5568 __alloc_pages+0x1ec/0x248 Call trace: __alloc_pages+0x1ec/0x248
    __kmalloc_large_node+0xc0/0x1f8 __kmalloc_node+0x134/0x1e8 rb_alloc_aux+0xe0/0x298 perf_mmap+0x440/0x660
    mmap_region+0x308/0x8a8 do_mmap+0x3c0/0x528 vm_mmap_pgoff+0xf4/0x1b8 ksys_mmap_pgoff+0x18c/0x218
    __arm64_sys_mmap+0x38/0x58 invoke_syscall+0x50/0x128 el0_svc_common.constprop.0+0x58/0x188
    do_el0_svc+0x34/0x50 el0_svc+0x34/0x108 el0t_64_sync_handler+0xb8/0xc0 el0t_64_sync+0x1a4/0x1a8
    'rb->aux_pages' allocated by kcalloc() is a pointer array which is used to maintains AUX trace pages. The
    allocated page for this array is physically contiguous (and virtually contiguous) with an order of
    0..MAX_ORDER. If the size of pointer array crosses the limitation set by MAX_ORDER, it reveals a WARNING.
    So bail out early with -ENOMEM if the request AUX area is out of bound, e.g.: #perf record -C 0 -m ,4G -e
    arm_spe_0// -- sleep 1 failed to mmap with 12 (Cannot allocate memory) (CVE-2023-52835)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52835");

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
