#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231501);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-56534");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-56534");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: isofs: avoid memory leak in iocharset
    A memleak was found as below: unreferenced object 0xffff0000d10164d8 (size 8): comm pool-udisksd, pid
    108217, jiffies 4295408555 hex dump (first 8 bytes): 75 74 66 38 00 cc cc cc utf8.... backtrace (crc
    de430d31): [<ffff800081046e6c>] kmemleak_alloc+0xb8/0xc8 [<ffff8000803e6c3c>]
    __kmalloc_node_track_caller_noprof+0x380/0x474 [<ffff800080363b74>] kstrdup+0x70/0xfc [<ffff80007bb3c6a4>]
    isofs_parse_param+0x228/0x2c0 [isofs] [<ffff8000804d7f68>] vfs_parse_fs_param+0xf4/0x164
    [<ffff8000804d8064>] vfs_parse_fs_string+0x8c/0xd4 [<ffff8000804d815c>] vfs_parse_monolithic_sep+0xb0/0xfc
    [<ffff8000804d81d8>] generic_parse_monolithic+0x30/0x3c [<ffff8000804d8bfc>]
    parse_monolithic_mount_data+0x40/0x4c [<ffff8000804b6a64>] path_mount+0x6c4/0x9ec [<ffff8000804b6e38>]
    do_mount+0xac/0xc4 [<ffff8000804b7494>] __arm64_sys_mount+0x16c/0x2b0 [<ffff80008002b8dc>]
    invoke_syscall+0x7c/0x104 [<ffff80008002ba44>] el0_svc_common.constprop.1+0xe0/0x104 [<ffff80008002ba94>]
    do_el0_svc+0x2c/0x38 [<ffff800081041108>] el0_svc+0x3c/0x1b8 The opt->iocharset is freed inside the
    isofs_fill_super function, But there may be situations where it's not possible to enter this function. For
    example, in the get_tree_bdev_flags function,when encountering the situation where Can't mount, would
    change RO state, In such a case, isofs_fill_super will not have the opportunity to be called,which means
    that opt->iocharset will not have the chance to be freed,ultimately leading to a memory leak. Let's move
    the memory freeing of opt->iocharset into isofs_free_fc function. (CVE-2024-56534)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-56534");

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
