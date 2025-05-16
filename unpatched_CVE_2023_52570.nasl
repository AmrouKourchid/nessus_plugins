#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226269);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52570");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52570");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: vfio/mdev: Fix a null-ptr-deref bug
    for mdev_unregister_parent() Inject fault while probing mdpy.ko, if kstrdup() of create_dir() fails in
    kobject_add_internal() in kobject_init_and_add() in mdev_type_add() in parent_create_sysfs_files(), it
    will return 0 and probe successfully. And when rmmod mdpy.ko, the mdpy_dev_exit() will call
    mdev_unregister_parent(), the mdev_type_remove() may traverse uninitialized parent->types[i] in
    parent_remove_sysfs_files(), and it will cause below null-ptr-deref. If mdev_type_add() fails, return the
    error code and kset_unregister() to fix the issue. general protection fault, probably for non-canonical
    address 0xdffffc0000000002: 0000 [#1] PREEMPT SMP KASAN KASAN: null-ptr-deref in range
    [0x0000000000000010-0x0000000000000017] CPU: 2 PID: 10215 Comm: rmmod Tainted: G W N 6.6.0-rc2+ #20
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 RIP:
    0010:__kobject_del+0x62/0x1c0 Code: 48 89 fa 48 c1 ea 03 80 3c 02 00 0f 85 51 01 00 00 48 b8 00 00 00 00
    00 fc ff df 48 8b 6b 28 48 8d 7d 10 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 24 01 00 00 48 8b 75 10 48 89
    df 48 8d 6b 3c e8 RSP: 0018:ffff88810695fd30 EFLAGS: 00010202 RAX: dffffc0000000000 RBX: ffffffffa0270268
    RCX: 0000000000000000 RDX: 0000000000000002 RSI: 0000000000000004 RDI: 0000000000000010 RBP:
    0000000000000000 R08: 0000000000000001 R09: ffffed10233a4ef1 R10: ffff888119d2778b R11: 0000000063666572
    R12: 0000000000000000 R13: fffffbfff404e2d4 R14: dffffc0000000000 R15: ffffffffa0271660 FS:
    00007fbc81981540(0000) GS:ffff888119d00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 00007fc14a142dc0 CR3: 0000000110a62003 CR4: 0000000000770ee0 DR0: ffffffff8fb0bce8
    DR1: ffffffff8fb0bce9 DR2: ffffffff8fb0bcea DR3: ffffffff8fb0bceb DR6: 00000000fffe0ff0 DR7:
    0000000000000600 PKRU: 55555554 Call Trace: <TASK> ? die_addr+0x3d/0xa0 ?
    exc_general_protection+0x144/0x220 ? asm_exc_general_protection+0x22/0x30 ? __kobject_del+0x62/0x1c0
    kobject_del+0x32/0x50 parent_remove_sysfs_files+0xd6/0x170 [mdev] mdev_unregister_parent+0xfb/0x190 [mdev]
    ? mdev_register_parent+0x270/0x270 [mdev] ? find_module_all+0x9d/0xe0 mdpy_dev_exit+0x17/0x63 [mdpy]
    __do_sys_delete_module.constprop.0+0x2fa/0x4b0 ? module_flags+0x300/0x300 ? __fput+0x4e7/0xa00
    do_syscall_64+0x35/0x80 entry_SYSCALL_64_after_hwframe+0x46/0xb0 RIP: 0033:0x7fbc813221b7 Code: 73 01 c3
    48 8b 0d d1 8c 2c 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00 b8 b0 00
    00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d a1 8c 2c 00 f7 d8 64 89 01 48 RSP: 002b:00007ffe780e0648
    EFLAGS: 00000206 ORIG_RAX: 00000000000000b0 RAX: ffffffffffffffda RBX: 00007ffe780e06a8 RCX:
    00007fbc813221b7 RDX: 000000000000000a RSI: 0000000000000800 RDI: 000055e214df9b58 RBP: 000055e214df9af0
    R08: 00007ffe780df5c1 R09: 0000000000000000 R10: 00007fbc8139ecc0 R11: 0000000000000206 R12:
    00007ffe780e0870 R13: 00007ffe780e0ed0 R14: 000055e214df9260 R15: 000055e214df9af0 </TASK> Modules linked
    in: mdpy(-) mdev vfio_iommu_type1 vfio [last unloaded: mdpy] Dumping ftrace buffer: (ftrace buffer empty)
    ---[ end trace 0000000000000000 ]--- RIP: 0010:__kobject_del+0x62/0x1c0 Code: 48 89 fa 48 c1 ea 03 80 3c
    02 00 0f 85 51 01 00 00 48 b8 00 00 00 00 00 fc ff df 48 8b 6b 28 48 8d 7d 10 48 89 fa 48 c1 ea 03 <80> 3c
    02 00 0f 85 24 01 00 00 48 8b 75 10 48 89 df 48 8d 6b 3c e8 RSP: 0018:ffff88810695fd30 EFLAGS: 00010202
    RAX: dffffc0000000000 RBX: ffffffffa0270268 RCX: 0000000000000000 RDX: 0000000000000002 RSI:
    0000000000000004 RDI: 0000000000000010 RBP: 0000000000000000 R08: 0000000000000001 R09: ffffed10233a4ef1
    R10: ffff888119d2778b R11: 0000000063666572 R12: 0000000000000000 R13: fffffbfff404e2d4 R14:
    dffffc0000000000 R15: ffffffffa0271660 FS: 00007fbc81981540(0000) GS:ffff888119d00000(000 ---truncated---
    (CVE-2023-52570)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52570");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/02");
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
