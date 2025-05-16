#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230434);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-50214");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-50214");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/connector: hdmi: Fix memory leak
    in drm_display_mode_from_cea_vic() modprobe drm_connector_test and then rmmod drm_connector_test, the
    following memory leak occurs. The `mode` allocated in drm_mode_duplicate() called by
    drm_display_mode_from_cea_vic() is not freed, which cause the memory leak: unreferenced object
    0xffffff80cb0ee400 (size 128): comm kunit_try_catch, pid 1948, jiffies 4294950339 hex dump (first 32
    bytes): 14 44 02 00 80 07 d8 07 04 08 98 08 00 00 38 04 .D............8. 3c 04 41 04 65 04 00 00 05 00 00
    00 00 00 00 00 <.A.e........... backtrace (crc 90e9585c): [<00000000ec42e3d7>] kmemleak_alloc+0x34/0x40
    [<00000000d0ef055a>] __kmalloc_cache_noprof+0x26c/0x2f4 [<00000000c2062161>] drm_mode_duplicate+0x44/0x19c
    [<00000000f96c74aa>] drm_display_mode_from_cea_vic+0x88/0x98 [<00000000d8f2c8b4>] 0xffffffdc982a4868
    [<000000005d164dbc>] kunit_try_run_case+0x13c/0x3ac [<000000006fb23398>]
    kunit_generic_run_threadfn_adapter+0x80/0xec [<000000006ea56ca0>] kthread+0x2e8/0x374 [<000000000676063f>]
    ret_from_fork+0x10/0x20 ...... Free `mode` by using drm_kunit_display_mode_from_cea_vic() to fix it.
    (CVE-2024-50214)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/09");
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
