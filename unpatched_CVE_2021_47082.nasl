#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224349);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47082");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47082");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tun: avoid double free in
    tun_free_netdev Avoid double free in tun_free_netdev() by moving the dev->tstats and tun->security allocs
    to a new ndo_init routine (tun_net_init()) that will be called by register_netdevice(). ndo_init is paired
    with the desctructor (tun_free_netdev()), so if there's an error in register_netdevice() the destructor
    will handle the frees. BUG: KASAN: double-free or invalid-free in selinux_tun_dev_free_security+0x1a/0x20
    security/selinux/hooks.c:5605 CPU: 0 PID: 25750 Comm: syz-executor416 Not tainted 5.16.0-rc2-syzk #1
    Hardware name: Red Hat KVM, BIOS Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline]
    dump_stack_lvl+0x89/0xb5 lib/dump_stack.c:106 print_address_description.constprop.9+0x28/0x160
    mm/kasan/report.c:247 kasan_report_invalid_free+0x55/0x80 mm/kasan/report.c:372 ____kasan_slab_free
    mm/kasan/common.c:346 [inline] __kasan_slab_free+0x107/0x120 mm/kasan/common.c:374 kasan_slab_free
    include/linux/kasan.h:235 [inline] slab_free_hook mm/slub.c:1723 [inline] slab_free_freelist_hook
    mm/slub.c:1749 [inline] slab_free mm/slub.c:3513 [inline] kfree+0xac/0x2d0 mm/slub.c:4561
    selinux_tun_dev_free_security+0x1a/0x20 security/selinux/hooks.c:5605
    security_tun_dev_free_security+0x4f/0x90 security/security.c:2342 tun_free_netdev+0xe6/0x150
    drivers/net/tun.c:2215 netdev_run_todo+0x4df/0x840 net/core/dev.c:10627 rtnl_unlock+0x13/0x20
    net/core/rtnetlink.c:112 __tun_chr_ioctl+0x80c/0x2870 drivers/net/tun.c:3302 tun_chr_ioctl+0x2f/0x40
    drivers/net/tun.c:3311 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:874 [inline]
    __se_sys_ioctl fs/ioctl.c:860 [inline] __x64_sys_ioctl+0x19d/0x220 fs/ioctl.c:860 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x3a/0x80 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2021-47082)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
    "name": [
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-headers-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-tools-5.4.0-1010-azure",
     "linux-udebs-azure"
    ],
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
