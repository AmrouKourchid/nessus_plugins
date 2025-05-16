#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229787);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47133");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47133");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: HID: amd_sfh: Fix memory leak in
    amd_sfh_work Kmemleak tool detected a memory leak in the amd_sfh driver. ==================== unreferenced
    object 0xffff88810228ada0 (size 32): comm insmod, pid 3968, jiffies 4295056001 (age 775.792s) hex dump
    (first 32 bytes): 00 20 73 1f 81 88 ff ff 00 01 00 00 00 00 ad de . s............. 22 01 00 00 00 00 ad de
    01 00 02 00 00 00 00 00 ............... backtrace: [<000000007b4c8799>]
    kmem_cache_alloc_trace+0x163/0x4f0 [<0000000005326893>] amd_sfh_get_report+0xa4/0x1d0 [amd_sfh]
    [<000000002a9e5ec4>] amdtp_hid_request+0x62/0x80 [amd_sfh] [<00000000b8a95807>]
    sensor_hub_get_feature+0x145/0x270 [hid_sensor_hub] [<00000000fda054ee>]
    hid_sensor_parse_common_attributes+0x215/0x460 [hid_sensor_iio_common] [<0000000021279ecf>]
    hid_accel_3d_probe+0xff/0x4a0 [hid_sensor_accel_3d] [<00000000915760ce>] platform_probe+0x6a/0xd0
    [<0000000060258a1f>] really_probe+0x192/0x620 [<00000000fa812f2d>] driver_probe_device+0x14a/0x1d0
    [<000000005e79f7fd>] __device_attach_driver+0xbd/0x110 [<0000000070d15018>] bus_for_each_drv+0xfd/0x160
    [<0000000013a3c312>] __device_attach+0x18b/0x220 [<000000008c7b4afc>] device_initial_probe+0x13/0x20
    [<00000000e6e99665>] bus_probe_device+0xfe/0x120 [<00000000833fa90b>] device_add+0x6a6/0xe00
    [<00000000fa901078>] platform_device_add+0x180/0x380 ==================== The fix is to freeing
    request_list entry once the processed entry is removed from the request_list. (CVE-2021-47133)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/15");
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
        "os_version": "8"
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
