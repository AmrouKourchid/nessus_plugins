#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227536);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-26944");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26944");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: zoned: fix use-after-free in
    do_zone_finish() Shinichiro reported the following use-after-free triggered by the device replace
    operation in fstests btrfs/070. BTRFS info (device nullb1): scrub: finished on devid 1 with status: 0
    ================================================================== BUG: KASAN: slab-use-after-free in
    do_zone_finish+0x91a/0xb90 [btrfs] Read of size 8 at addr ffff8881543c8060 by task btrfs-cleaner/3494007
    CPU: 0 PID: 3494007 Comm: btrfs-cleaner Tainted: G W 6.8.0-rc5-kts #1 Hardware name: Supermicro Super
    Server/X11SPi-TF, BIOS 3.3 02/21/2020 Call Trace: <TASK> dump_stack_lvl+0x5b/0x90 print_report+0xcf/0x670
    ? __virt_addr_valid+0x200/0x3e0 kasan_report+0xd8/0x110 ? do_zone_finish+0x91a/0xb90 [btrfs] ?
    do_zone_finish+0x91a/0xb90 [btrfs] do_zone_finish+0x91a/0xb90 [btrfs] btrfs_delete_unused_bgs+0x5e1/0x1750
    [btrfs] ? __pfx_btrfs_delete_unused_bgs+0x10/0x10 [btrfs] ? btrfs_put_root+0x2d/0x220 [btrfs] ?
    btrfs_clean_one_deleted_snapshot+0x299/0x430 [btrfs] cleaner_kthread+0x21e/0x380 [btrfs] ?
    __pfx_cleaner_kthread+0x10/0x10 [btrfs] kthread+0x2e3/0x3c0 ? __pfx_kthread+0x10/0x10
    ret_from_fork+0x31/0x70 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK> Allocated by task
    3493983: kasan_save_stack+0x33/0x60 kasan_save_track+0x14/0x30 __kasan_kmalloc+0xaa/0xb0
    btrfs_alloc_device+0xb3/0x4e0 [btrfs] device_list_add.constprop.0+0x993/0x1630 [btrfs]
    btrfs_scan_one_device+0x219/0x3d0 [btrfs] btrfs_control_ioctl+0x26e/0x310 [btrfs]
    __x64_sys_ioctl+0x134/0x1b0 do_syscall_64+0x99/0x190 entry_SYSCALL_64_after_hwframe+0x6e/0x76 Freed by
    task 3494056: kasan_save_stack+0x33/0x60 kasan_save_track+0x14/0x30 kasan_save_free_info+0x3f/0x60
    poison_slab_object+0x102/0x170 __kasan_slab_free+0x32/0x70 kfree+0x11b/0x320
    btrfs_rm_dev_replace_free_srcdev+0xca/0x280 [btrfs] btrfs_dev_replace_finishing+0xd7e/0x14f0 [btrfs]
    btrfs_dev_replace_by_ioctl+0x1286/0x25a0 [btrfs] btrfs_ioctl+0xb27/0x57d0 [btrfs]
    __x64_sys_ioctl+0x134/0x1b0 do_syscall_64+0x99/0x190 entry_SYSCALL_64_after_hwframe+0x6e/0x76 The buggy
    address belongs to the object at ffff8881543c8000 which belongs to the cache kmalloc-1k of size 1024 The
    buggy address is located 96 bytes inside of freed 1024-byte region [ffff8881543c8000, ffff8881543c8400)
    The buggy address belongs to the physical page: page:00000000fe2c1285 refcount:1 mapcount:0
    mapping:0000000000000000 index:0x0 pfn:0x1543c8 head:00000000fe2c1285 order:3 entire_mapcount:0
    nr_pages_mapped:0 pincount:0 flags: 0x17ffffc0000840(slab|head|node=0|zone=2|lastcpupid=0x1fffff)
    page_type: 0xffffffff() raw: 0017ffffc0000840 ffff888100042dc0 ffffea0019e8f200 dead000000000002 raw:
    0000000000000000 0000000000100010 00000001ffffffff 0000000000000000 page dumped because: kasan: bad access
    detected Memory state around the buggy address: ffff8881543c7f00: 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 ffff8881543c7f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 >ffff8881543c8000: fa fb fb fb
    fb fb fb fb fb fb fb fb fb fb fb fb ^ ffff8881543c8080: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
    ffff8881543c8100: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb This UAF happens because we're accessing
    stale zone information of a already removed btrfs_device in do_zone_finish(). The sequence of events is as
    follows: btrfs_dev_replace_start btrfs_scrub_dev btrfs_dev_replace_finishing
    btrfs_dev_replace_update_device_in_mapping_tree <-- devices replaced btrfs_rm_dev_replace_free_srcdev
    btrfs_free_device <-- device freed cleaner_kthread btrfs_delete_unused_bgs btrfs_zone_finish
    do_zone_finish <-- refers the freed device The reason for this is that we're using a ---truncated---
    (CVE-2024-26944)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26944");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
     "btrfs-modules-6.1.0-29-alpha-generic-di",
     "cdrom-core-modules-6.1.0-29-alpha-generic-di",
     "ext4-modules-6.1.0-29-alpha-generic-di",
     "fat-modules-6.1.0-29-alpha-generic-di",
     "isofs-modules-6.1.0-29-alpha-generic-di",
     "jfs-modules-6.1.0-29-alpha-generic-di",
     "kernel-image-6.1.0-29-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-29-common",
     "linux-headers-6.1.0-29-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-29",
     "loop-modules-6.1.0-29-alpha-generic-di",
     "nic-modules-6.1.0-29-alpha-generic-di",
     "nic-shared-modules-6.1.0-29-alpha-generic-di",
     "nic-wireless-modules-6.1.0-29-alpha-generic-di",
     "pata-modules-6.1.0-29-alpha-generic-di",
     "ppp-modules-6.1.0-29-alpha-generic-di",
     "scsi-core-modules-6.1.0-29-alpha-generic-di",
     "scsi-modules-6.1.0-29-alpha-generic-di",
     "scsi-nic-modules-6.1.0-29-alpha-generic-di",
     "serial-modules-6.1.0-29-alpha-generic-di",
     "usb-serial-modules-6.1.0-29-alpha-generic-di",
     "xfs-modules-6.1.0-29-alpha-generic-di"
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
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "12"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
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
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
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
