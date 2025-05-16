#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225692);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49021");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49021");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: phy: fix null-ptr-deref while
    probe() failed I got a null-ptr-deref report as following when doing fault injection test: BUG: kernel
    NULL pointer dereference, address: 0000000000000058 Oops: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 1 PID: 253
    Comm: 507-spi-dm9051 Tainted: G B N 6.1.0-rc3+ Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
    1.13.0-1ubuntu1.1 04/01/2014 RIP: 0010:klist_put+0x2d/0xd0 Call Trace: <TASK> klist_remove+0xf1/0x1c0
    device_release_driver_internal+0x23e/0x2d0 bus_remove_device+0x1bd/0x240 device_del+0x357/0x770
    phy_device_remove+0x11/0x30 mdiobus_unregister+0xa5/0x140 release_nodes+0x6a/0xa0
    devres_release_all+0xf8/0x150 device_unbind_cleanup+0x19/0xd0 //probe path: phy_device_register()
    device_add() phy_connect phy_attach_direct() //set device driver probe() //it's failed, driver is not
    bound device_bind_driver() // probe failed, it's not called //remove path: phy_device_remove()
    device_del() device_release_driver_internal() __device_release_driver() //dev->drv is not NULL
    klist_remove() <- knode_driver is not added yet, cause null-ptr-deref In phy_attach_direct(), after
    setting the 'dev->driver', probe() fails, device_bind_driver() is not called, so the knode_driver->n_klist
    is not set, then it causes null-ptr-deref in __device_release_driver() while deleting device. Fix this by
    setting dev->driver to NULL in the error path in phy_attach_direct(). (CVE-2022-49021)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49021");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
