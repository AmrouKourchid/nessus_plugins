#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228372);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41097");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41097");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: usb: atm: cxacru: fix endpoint
    checking in cxacru_bind() Syzbot is still reporting quite an old issue [1] that occurs due to incomplete
    checking of present usb endpoints. As such, wrong endpoints types may be used at urb sumbitting stage
    which in turn triggers a warning in usb_submit_urb(). Fix the issue by verifying that required endpoint
    types are present for both in and out endpoints, taking into account cmd endpoint type. Unfortunately,
    this patch has not been tested on real hardware. [1] Syzbot report: usb 1-1: BOGUS urb xfer, pipe 1 !=
    type 3 WARNING: CPU: 0 PID: 8667 at drivers/usb/core/urb.c:502 usb_submit_urb+0xed2/0x18a0
    drivers/usb/core/urb.c:502 Modules linked in: CPU: 0 PID: 8667 Comm: kworker/0:4 Not tainted
    5.14.0-rc4-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google
    01/01/2011 Workqueue: usb_hub_wq hub_event RIP: 0010:usb_submit_urb+0xed2/0x18a0
    drivers/usb/core/urb.c:502 ... Call Trace: cxacru_cm+0x3c0/0x8e0 drivers/usb/atm/cxacru.c:649
    cxacru_card_status+0x22/0xd0 drivers/usb/atm/cxacru.c:760 cxacru_bind+0x7ac/0x11a0
    drivers/usb/atm/cxacru.c:1209 usbatm_usb_probe+0x321/0x1ae0 drivers/usb/atm/usbatm.c:1055
    cxacru_usb_probe+0xdf/0x1e0 drivers/usb/atm/cxacru.c:1363 usb_probe_interface+0x315/0x7f0
    drivers/usb/core/driver.c:396 call_driver_probe drivers/base/dd.c:517 [inline] really_probe+0x23c/0xcd0
    drivers/base/dd.c:595 __driver_probe_device+0x338/0x4d0 drivers/base/dd.c:747
    driver_probe_device+0x4c/0x1a0 drivers/base/dd.c:777 __device_attach_driver+0x20b/0x2f0
    drivers/base/dd.c:894 bus_for_each_drv+0x15f/0x1e0 drivers/base/bus.c:427 __device_attach+0x228/0x4a0
    drivers/base/dd.c:965 bus_probe_device+0x1e4/0x290 drivers/base/bus.c:487 device_add+0xc2f/0x2180
    drivers/base/core.c:3354 usb_set_configuration+0x113a/0x1910 drivers/usb/core/message.c:2170
    usb_generic_driver_probe+0xba/0x100 drivers/usb/core/generic.c:238 usb_probe_device+0xd9/0x2c0
    drivers/usb/core/driver.c:293 (CVE-2024-41097)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
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
