#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230443);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-50213");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-50213");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/tests: hdmi: Fix memory leaks in
    drm_display_mode_from_cea_vic() modprobe drm_hdmi_state_helper_test and then rmmod it, the following
    memory leak occurs. The `mode` allocated in drm_mode_duplicate() called by drm_display_mode_from_cea_vic()
    is not freed, which cause the memory leak: unreferenced object 0xffffff80ccd18100 (size 128): comm
    kunit_try_catch, pid 1851, jiffies 4295059695 hex dump (first 32 bytes): 57 62 00 00 80 02 90 02 f0 02
    20 03 00 00 e0 01 Wb........ ..... ea 01 ec 01 0d 02 00 00 0a 00 00 00 00 00 00 00 ................
    backtrace (crc c2f1aa95): [<000000000f10b11b>] kmemleak_alloc+0x34/0x40 [<000000001cd4cf73>]
    __kmalloc_cache_noprof+0x26c/0x2f4 [<00000000f1f3cffa>] drm_mode_duplicate+0x44/0x19c [<000000008cbeef13>]
    drm_display_mode_from_cea_vic+0x88/0x98 [<0000000019daaacf>] 0xffffffedc11ae69c [<000000000aad0f85>]
    kunit_try_run_case+0x13c/0x3ac [<00000000a9210bac>] kunit_generic_run_threadfn_adapter+0x80/0xec
    [<000000000a0b2e9e>] kthread+0x2e8/0x374 [<00000000bd668858>] ret_from_fork+0x10/0x20 ...... Free `mode`
    by using drm_kunit_display_mode_from_cea_vic() to fix it. (CVE-2024-50213)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50213");

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
