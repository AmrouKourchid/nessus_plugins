#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229819);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47561");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47561");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: i2c: virtio: disable timeout handling
    If a timeout is hit, it can result is incorrect data on the I2C bus and/or memory corruptions in the guest
    since the device can still be operating on the buffers it was given while the guest has freed them. Here
    is, for example, the start of a slub_debug splat which was triggered on the next transfer after one
    transfer was forced to timeout by setting a breakpoint in the backend (rust-vmm/vhost-device): BUG
    kmalloc-1k (Not tainted): Poison overwritten First byte 0x1 instead of 0x6b Allocated in
    virtio_i2c_xfer+0x65/0x35c age=350 cpu=0 pid=29 __kmalloc+0xc2/0x1c9 virtio_i2c_xfer+0x65/0x35c
    __i2c_transfer+0x429/0x57d i2c_transfer+0x115/0x134 i2cdev_ioctl_rdwr+0x16a/0x1de i2cdev_ioctl+0x247/0x2ed
    vfs_ioctl+0x21/0x30 sys_ioctl+0xb18/0xb41 Freed in virtio_i2c_xfer+0x32e/0x35c age=244 cpu=0 pid=29
    kfree+0x1bd/0x1cc virtio_i2c_xfer+0x32e/0x35c __i2c_transfer+0x429/0x57d i2c_transfer+0x115/0x134
    i2cdev_ioctl_rdwr+0x16a/0x1de i2cdev_ioctl+0x247/0x2ed vfs_ioctl+0x21/0x30 sys_ioctl+0xb18/0xb41 There is
    no simple fix for this (the driver would have to always create bounce buffers and hold on to them until
    the device eventually returns the buffers), so just disable the timeout support for now. (CVE-2021-47561)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47561");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/24");
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
