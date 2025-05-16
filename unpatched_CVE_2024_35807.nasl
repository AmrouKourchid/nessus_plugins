#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228319);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35807");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35807");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ext4: fix corruption during on-line
    resize We observed a corruption during on-line resize of a file system that is larger than 16 TiB with 4k
    block size. With having more then 2^32 blocks resize_inode is turned off by default by mke2fs. The issue
    can be reproduced on a smaller file system for convenience by explicitly turning off resize_inode. An on-
    line resize across an 8 GiB boundary (the size of a meta block group in this setup) then leads to a
    corruption: dev=/dev/<some_dev> # should be >= 16 GiB mkdir -p /corruption /sbin/mke2fs -t ext4 -b 4096 -O
    ^resize_inode $dev $((2 * 2**21 - 2**15)) mount -t ext4 $dev /corruption dd if=/dev/zero bs=4096
    of=/corruption/test count=$((2*2**21 - 4*2**15)) sha1sum /corruption/test #
    79d2658b39dcfd77274e435b0934028adafaab11 /corruption/test /sbin/resize2fs $dev $((2*2**21)) # drop page
    cache to force reload the block from disk echo 1 > /proc/sys/vm/drop_caches sha1sum /corruption/test #
    3c2abc63cbf1a94c9e6977e0fbd72cd832c4d5c3 /corruption/test 2^21 = 2^15*2^6 equals 8 GiB whereof 2^15 is the
    number of blocks per block group and 2^6 are the number of block groups that make a meta block group. The
    last checksum might be different depending on how the file is laid out across the physical blocks. The
    actual corruption occurs at physical block 63*2^15 = 2064384 which would be the location of the backup of
    the meta block group's block descriptor. During the on-line resize the file system will be converted to
    meta_bg starting at s_first_meta_bg which is 2 in the example - meaning all block groups after 16 GiB.
    However, in ext4_flex_group_add we might add block groups that are not part of the first meta block group
    yet. In the reproducer we achieved this by substracting the size of a whole block group from the point
    where the meta block group would start. This must be considered when updating the backup block group
    descriptors to follow the non-meta_bg layout. The fix is to add a test whether the group to add is already
    part of the meta block group or not. (CVE-2024-35807)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35807");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/10");
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
