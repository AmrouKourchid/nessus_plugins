#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229869);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47272");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47272");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: usb: dwc3: gadget: Bail from
    dwc3_gadget_exit() if dwc->gadget is NULL There exists a possible scenario in which dwc3_gadget_init() can
    fail: during during host -> peripheral mode switch in dwc3_set_mode(), and a pending gadget driver fails
    to bind. Then, if the DRD undergoes another mode switch from peripheral->host the resulting
    dwc3_gadget_exit() will attempt to reference an invalid and dangling dwc->gadget pointer as well as call
    dma_free_coherent() on unmapped DMA pointers. The exact scenario can be reproduced as follows: - Start
    DWC3 in peripheral mode - Configure ConfigFS gadget with FunctionFS instance (or use g_ffs) - Run
    FunctionFS userspace application (open EPs, write descriptors, etc) - Bind gadget driver to DWC3's UDC -
    Switch DWC3 to host mode => dwc3_gadget_exit() is called. usb_del_gadget() will put the ConfigFS driver
    instance on the gadget_driver_pending_list - Stop FunctionFS application (closes the ep files) - Switch
    DWC3 to peripheral mode => dwc3_gadget_init() fails as usb_add_gadget() calls
    check_pending_gadget_drivers() and attempts to rebind the UDC to the ConfigFS gadget but fails with -19
    (-ENODEV) because the FFS instance is not in FFS_ACTIVE state (userspace has not re-opened and written the
    descriptors yet, i.e. desc_ready!=0). - Switch DWC3 back to host mode => dwc3_gadget_exit() is called
    again, but this time dwc->gadget is invalid. Although it can be argued that userspace should take
    responsibility for ensuring that the FunctionFS application be ready prior to allowing the composite
    driver bind to the UDC, failure to do so should not result in a panic from the kernel driver. Fix this by
    setting dwc->gadget to NULL in the failure path of dwc3_gadget_init() and add a check to
    dwc3_gadget_exit() to bail out unless the gadget pointer is valid. (CVE-2021-47272)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
