#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229468);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-47680");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-47680");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: f2fs: check discard support for
    conventional zones As the helper function f2fs_bdev_support_discard() shows, f2fs checks if the target
    block devices support discard by calling bdev_max_discard_sectors() and bdev_is_zoned(). This check works
    well for most cases, but it does not work for conventional zones on zoned block devices. F2fs assumes that
    zoned block devices support discard, and calls __submit_discard_cmd(). When __submit_discard_cmd() is
    called for sequential write required zones, it works fine since __submit_discard_cmd() issues zone reset
    commands instead of discard commands. However, when __submit_discard_cmd() is called for conventional
    zones, __blkdev_issue_discard() is called even when the devices do not support discard. The inappropriate
    __blkdev_issue_discard() call was not a problem before the commit 30f1e7241422 (block: move discard
    checks into the ioctl handler) because __blkdev_issue_discard() checked if the target devices support
    discard or not. If not, it returned EOPNOTSUPP. After the commit, __blkdev_issue_discard() no longer
    checks it. It always returns zero and sets NULL to the given bio pointer. This NULL pointer triggers
    f2fs_bug_on() in __submit_discard_cmd(). The BUG is recreated with the commands below at the umount step,
    where /dev/nullb0 is a zoned null_blk with 5GB total size, 128MB zone size and 10 conventional zones. $
    mkfs.f2fs -f -m /dev/nullb0 $ mount /dev/nullb0 /mnt $ for ((i=0;i<5;i++)); do dd if=/dev/zero
    of=/mnt/test bs=65536 count=1600 conv=fsync; done $ umount /mnt To fix the BUG, avoid the inappropriate
    __blkdev_issue_discard() call. When discard is requested for conventional zones, check if the device
    supports discard or not. If not, return EOPNOTSUPP. (CVE-2024-47680)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47680");

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
