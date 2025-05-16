#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230592);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53238");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53238");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Bluetooth: btmtk: adjust the position
    to init iso data anchor MediaTek iso data anchor init should be moved to where MediaTek claims iso data
    interface. If there is an unexpected BT usb disconnect during setup flow, it will cause a NULL pointer
    crash issue when releasing iso anchor since the anchor wasn't been init yet. Adjust the position to do iso
    data anchor init. [ 17.137991] pc : usb_kill_anchored_urbs+0x60/0x168 [ 17.137998] lr :
    usb_kill_anchored_urbs+0x44/0x168 [ 17.137999] sp : ffffffc0890cb5f0 [ 17.138000] x29: ffffffc0890cb5f0
    x28: ffffff80bb6c2e80 [ 17.144081] gpio gpiochip0: registered chardev handle for 1 lines [ 17.148421] x27:
    0000000000000000 [ 17.148422] x26: ffffffd301ff4298 x25: 0000000000000003 x24: 00000000000000f0 [
    17.148424] x23: 0000000000000000 x22: 00000000ffffffff x21: 0000000000000001 [ 17.148425] x20:
    ffffffffffffffd8 x19: ffffff80c0f25560 x18: 0000000000000000 [ 17.148427] x17: ffffffd33864e408 x16:
    ffffffd33808f7c8 x15: 0000000000200000 [ 17.232789] x14: e0cd73cf80ffffff x13: 50f2137c0a0338c9 x12:
    0000000000000001 [ 17.239912] x11: 0000000080150011 x10: 0000000000000002 x9 : 0000000000000001 [
    17.247035] x8 : 0000000000000000 x7 : 0000000000008080 x6 : 8080000000000000 [ 17.254158] x5 :
    ffffffd33808ebc0 x4 : fffffffe033dcf20 x3 : 0000000080150011 [ 17.261281] x2 : ffffff8087a91400 x1 :
    0000000000000000 x0 : ffffff80c0f25588 [ 17.268404] Call trace: [ 17.270841]
    usb_kill_anchored_urbs+0x60/0x168 [ 17.275274] btusb_mtk_release_iso_intf+0x2c/0xd8 [btusb (HASH:5afe 6)]
    [ 17.284226] btusb_mtk_disconnect+0x14/0x28 [btusb (HASH:5afe 6)] [ 17.292652] btusb_disconnect+0x70/0x140
    [btusb (HASH:5afe 6)] [ 17.300818] usb_unbind_interface+0xc4/0x240 [ 17.305079]
    device_release_driver_internal+0x18c/0x258 [ 17.310296] device_release_driver+0x1c/0x30 [ 17.314557]
    bus_remove_device+0x140/0x160 [ 17.318643] device_del+0x1c0/0x330 [ 17.322121]
    usb_disable_device+0x80/0x180 [ 17.326207] usb_disconnect+0xec/0x300 [ 17.329948] hub_quiesce+0x80/0xd0 [
    17.333339] hub_disconnect+0x44/0x190 [ 17.337078] usb_unbind_interface+0xc4/0x240 [ 17.341337]
    device_release_driver_internal+0x18c/0x258 [ 17.346551] device_release_driver+0x1c/0x30 [ 17.350810]
    usb_driver_release_interface+0x70/0x88 [ 17.355677] proc_ioctl+0x13c/0x228 [ 17.359157]
    proc_ioctl_default+0x50/0x80 [ 17.363155] usbdev_ioctl+0x830/0xd08 [ 17.366808]
    __arm64_sys_ioctl+0x94/0xd0 [ 17.370723] invoke_syscall+0x6c/0xf8 [ 17.374377] el0_svc_common+0x84/0xe0 [
    17.378030] do_el0_svc+0x20/0x30 [ 17.381334] el0_svc+0x34/0x60 [ 17.384382] el0t_64_sync_handler+0x88/0xf0
    [ 17.388554] el0t_64_sync+0x180/0x188 [ 17.392208] Code: f9400677 f100a2f4 54fffea0 d503201f (b8350288) [
    17.398289] ---[ end trace 0000000000000000 ]--- (CVE-2024-53238)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53238");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/27");
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
