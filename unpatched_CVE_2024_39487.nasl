#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229176);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-39487");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-39487");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bonding: Fix out-of-bounds read in
    bond_option_arp_ip_targets_set() In function bond_option_arp_ip_targets_set(), if newval->string is an
    empty string, newval->string+1 will point to the byte after the string, causing an out-of-bound read. BUG:
    KASAN: slab-out-of-bounds in strlen+0x7d/0xa0 lib/string.c:418 Read of size 1 at addr ffff8881119c4781 by
    task syz-executor665/8107 CPU: 1 PID: 8107 Comm: syz-executor665 Not tainted 6.7.0-rc7 #1 Hardware name:
    QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 Call Trace: <TASK> __dump_stack
    lib/dump_stack.c:88 [inline] dump_stack_lvl+0xd9/0x150 lib/dump_stack.c:106 print_address_description
    mm/kasan/report.c:364 [inline] print_report+0xc1/0x5e0 mm/kasan/report.c:475 kasan_report+0xbe/0xf0
    mm/kasan/report.c:588 strlen+0x7d/0xa0 lib/string.c:418 __fortify_strlen include/linux/fortify-
    string.h:210 [inline] in4_pton+0xa3/0x3f0 net/core/utils.c:130 bond_option_arp_ip_targets_set+0xc2/0x910
    drivers/net/bonding/bond_options.c:1201 __bond_opt_set+0x2a4/0x1030 drivers/net/bonding/bond_options.c:767
    __bond_opt_set_notify+0x48/0x150 drivers/net/bonding/bond_options.c:792 bond_opt_tryset_rtnl+0xda/0x160
    drivers/net/bonding/bond_options.c:817 bonding_sysfs_store_option+0xa1/0x120
    drivers/net/bonding/bond_sysfs.c:156 dev_attr_store+0x54/0x80 drivers/base/core.c:2366
    sysfs_kf_write+0x114/0x170 fs/sysfs/file.c:136 kernfs_fop_write_iter+0x337/0x500 fs/kernfs/file.c:334
    call_write_iter include/linux/fs.h:2020 [inline] new_sync_write fs/read_write.c:491 [inline]
    vfs_write+0x96a/0xd80 fs/read_write.c:584 ksys_write+0x122/0x250 fs/read_write.c:637 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0x40/0x110 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b ---[ end trace ]--- Fix it by adding a check of string length
    before using it. (CVE-2024-39487)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39487");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
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
