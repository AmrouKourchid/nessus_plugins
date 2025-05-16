#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225548);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48942");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48942");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: hwmon: Handle failure to register
    sensor with thermal zone correctly If an attempt is made to a sensor with a thermal zone and it fails, the
    call to devm_thermal_zone_of_sensor_register() may return -ENODEV. This may result in crashes similar to
    the following. Unable to handle kernel NULL pointer dereference at virtual address 00000000000003cd ...
    Internal error: Oops: 96000021 [#1] PREEMPT SMP ... pstate: 60400009 (nZCv daif +PAN -UAO -TCO -DIT -SSBS
    BTYPE=--) pc : mutex_lock+0x18/0x60 lr : thermal_zone_device_update+0x40/0x2e0 sp : ffff800014c4fc60 x29:
    ffff800014c4fc60 x28: ffff365ee3f6e000 x27: ffffdde218426790 x26: ffff365ee3f6e000 x25: 0000000000000000
    x24: ffff365ee3f6e000 x23: ffffdde218426870 x22: ffff365ee3f6e000 x21: 00000000000003cd x20:
    ffff365ee8bf3308 x19: ffffffffffffffed x18: 0000000000000000 x17: ffffdde21842689c x16: ffffdde1cb7a0b7c
    x15: 0000000000000040 x14: ffffdde21a4889a0 x13: 0000000000000228 x12: 0000000000000000 x11:
    0000000000000000 x10: 0000000000000000 x9 : 0000000000000000 x8 : 0000000001120000 x7 : 0000000000000001
    x6 : 0000000000000000 x5 : 0068000878e20f07 x4 : 0000000000000000 x3 : 00000000000003cd x2 :
    ffff365ee3f6e000 x1 : 0000000000000000 x0 : 00000000000003cd Call trace: mutex_lock+0x18/0x60
    hwmon_notify_event+0xfc/0x110 0xffffdde1cb7a0a90 0xffffdde1cb7a0b7c irq_thread_fn+0x2c/0xa0
    irq_thread+0x134/0x240 kthread+0x178/0x190 ret_from_fork+0x10/0x20 Code: d503201f d503201f d2800001
    aa0103e4 (c8e47c02) Jon Hunter reports that the exact call sequence is: hwmon_notify_event() -->
    hwmon_thermal_notify() --> thermal_zone_device_update() --> update_temperature() --> mutex_lock() The
    hwmon core needs to handle all errors returned from calls to devm_thermal_zone_of_sensor_register(). If
    the call fails with -ENODEV, report that the sensor was not attached to a thermal zone but continue to
    register the hwmon device. (CVE-2022-48942)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48942");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
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
    "name": "kernel-rt",
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
