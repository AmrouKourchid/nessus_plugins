#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224325);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47613");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47613");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: i2c: virtio: fix completion handling
    The driver currently assumes that the notify callback is only received when the device is done with all
    the queued buffers. However, this is not true, since the notify callback could be called without any of
    the queued buffers being completed (for example, with virtio-pci and shared interrupts) or with only some
    of the buffers being completed (since the driver makes them available to the device in multiple separate
    virtqueue_add_sgs() calls). This can lead to incorrect data on the I2C bus or memory corruption in the
    guest if the device operates on buffers which are have been freed by the driver. (The WARN_ON in the
    driver is also triggered.) BUG kmalloc-128 (Tainted: G W ): Poison overwritten First byte 0x0 instead of
    0x6b Allocated in i2cdev_ioctl_rdwr+0x9d/0x1de age=243 cpu=0 pid=28 memdup_user+0x2e/0xbd
    i2cdev_ioctl_rdwr+0x9d/0x1de i2cdev_ioctl+0x247/0x2ed vfs_ioctl+0x21/0x30 sys_ioctl+0xb18/0xb41 Freed in
    i2cdev_ioctl_rdwr+0x1bb/0x1de age=68 cpu=0 pid=28 kfree+0x1bd/0x1cc i2cdev_ioctl_rdwr+0x1bb/0x1de
    i2cdev_ioctl+0x247/0x2ed vfs_ioctl+0x21/0x30 sys_ioctl+0xb18/0xb41 Fix this by calling virtio_get_buf()
    from the notify handler like other virtio drivers and by actually waiting for all the buffers to be
    completed. (CVE-2021-47613)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
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
