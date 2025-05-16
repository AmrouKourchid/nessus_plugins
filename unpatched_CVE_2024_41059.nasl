#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228339);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41059");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41059");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: hfsplus: fix uninit-value in copy_name
    [syzbot reported] BUG: KMSAN: uninit-value in sized_strscpy+0xc4/0x160 sized_strscpy+0xc4/0x160
    copy_name+0x2af/0x320 fs/hfsplus/xattr.c:411 hfsplus_listxattr+0x11e9/0x1a50 fs/hfsplus/xattr.c:750
    vfs_listxattr fs/xattr.c:493 [inline] listxattr+0x1f3/0x6b0 fs/xattr.c:840 path_listxattr fs/xattr.c:864
    [inline] __do_sys_listxattr fs/xattr.c:876 [inline] __se_sys_listxattr fs/xattr.c:873 [inline]
    __x64_sys_listxattr+0x16b/0x2f0 fs/xattr.c:873 x64_sys_call+0x2ba0/0x3b50
    arch/x86/include/generated/asm/syscalls_64.h:195 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f Uninit was
    created at: slab_post_alloc_hook mm/slub.c:3877 [inline] slab_alloc_node mm/slub.c:3918 [inline]
    kmalloc_trace+0x57b/0xbe0 mm/slub.c:4065 kmalloc include/linux/slab.h:628 [inline]
    hfsplus_listxattr+0x4cc/0x1a50 fs/hfsplus/xattr.c:699 vfs_listxattr fs/xattr.c:493 [inline]
    listxattr+0x1f3/0x6b0 fs/xattr.c:840 path_listxattr fs/xattr.c:864 [inline] __do_sys_listxattr
    fs/xattr.c:876 [inline] __se_sys_listxattr fs/xattr.c:873 [inline] __x64_sys_listxattr+0x16b/0x2f0
    fs/xattr.c:873 x64_sys_call+0x2ba0/0x3b50 arch/x86/include/generated/asm/syscalls_64.h:195 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f [Fix] When allocating memory to strbuf, initialize memory to 0.
    (CVE-2024-41059)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41059");

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
    "name": "linux-azure-fde",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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
        "os_version": "20.04"
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
