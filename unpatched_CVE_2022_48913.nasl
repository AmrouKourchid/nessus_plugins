#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225213);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48913");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48913");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: blktrace: fix use after free for
    struct blk_trace When tracing the whole disk, 'dropped' and 'msg' will be created under 'q->debugfs_dir'
    and 'bt->dir' is NULL, thus blk_trace_free() won't remove those files. What's worse, the following UAF can
    be triggered because of accessing stale 'dropped' and 'msg':
    ================================================================== BUG: KASAN: use-after-free in
    blk_dropped_read+0x89/0x100 Read of size 4 at addr ffff88816912f3d8 by task blktrace/1188 CPU: 27 PID:
    1188 Comm: blktrace Not tainted 5.17.0-rc4-next-20220217+ #469 Hardware name: QEMU Standard PC (i440FX +
    PIIX, 1996), BIOS ?-20190727_073836-4 Call Trace: <TASK> dump_stack_lvl+0x34/0x44
    print_address_description.constprop.0.cold+0xab/0x381 ? blk_dropped_read+0x89/0x100 ?
    blk_dropped_read+0x89/0x100 kasan_report.cold+0x83/0xdf ? blk_dropped_read+0x89/0x100
    kasan_check_range+0x140/0x1b0 blk_dropped_read+0x89/0x100 ? blk_create_buf_file_callback+0x20/0x20 ?
    kmem_cache_free+0xa1/0x500 ? do_sys_openat2+0x258/0x460 full_proxy_read+0x8f/0xc0 vfs_read+0xc6/0x260
    ksys_read+0xb9/0x150 ? vfs_write+0x3d0/0x3d0 ? fpregs_assert_state_consistent+0x55/0x60 ?
    exit_to_user_mode_prepare+0x39/0x1e0 do_syscall_64+0x35/0x80 entry_SYSCALL_64_after_hwframe+0x44/0xae RIP:
    0033:0x7fbc080d92fd Code: ce 20 00 00 75 10 b8 00 00 00 00 0f 05 48 3d 01 f0 ff ff 73 31 c3 48 83 1 RSP:
    002b:00007fbb95ff9cb0 EFLAGS: 00000293 ORIG_RAX: 0000000000000000 RAX: ffffffffffffffda RBX:
    00007fbb95ff9dc0 RCX: 00007fbc080d92fd RDX: 0000000000000100 RSI: 00007fbb95ff9cc0 RDI: 0000000000000045
    RBP: 0000000000000045 R08: 0000000000406299 R09: 00000000fffffffd R10: 000000000153afa0 R11:
    0000000000000293 R12: 00007fbb780008c0 R13: 00007fbb78000938 R14: 0000000000608b30 R15: 00007fbb780029c8
    </TASK> Allocated by task 1050: kasan_save_stack+0x1e/0x40 __kasan_kmalloc+0x81/0xa0
    do_blk_trace_setup+0xcb/0x410 __blk_trace_setup+0xac/0x130 blk_trace_ioctl+0xe9/0x1c0
    blkdev_ioctl+0xf1/0x390 __x64_sys_ioctl+0xa5/0xe0 do_syscall_64+0x35/0x80
    entry_SYSCALL_64_after_hwframe+0x44/0xae Freed by task 1050: kasan_save_stack+0x1e/0x40
    kasan_set_track+0x21/0x30 kasan_set_free_info+0x20/0x30 __kasan_slab_free+0x103/0x180 kfree+0x9a/0x4c0
    __blk_trace_remove+0x53/0x70 blk_trace_ioctl+0x199/0x1c0 blkdev_common_ioctl+0x5e9/0xb30
    blkdev_ioctl+0x1a5/0x390 __x64_sys_ioctl+0xa5/0xe0 do_syscall_64+0x35/0x80
    entry_SYSCALL_64_after_hwframe+0x44/0xae The buggy address belongs to the object at ffff88816912f380 which
    belongs to the cache kmalloc-96 of size 96 The buggy address is located 88 bytes inside of 96-byte region
    [ffff88816912f380, ffff88816912f3e0) The buggy address belongs to the page: page:000000009a1b4e7c
    refcount:1 mapcount:0 mapping:0000000000000000 index:0x0f flags:
    0x17ffffc0000200(slab|node=0|zone=2|lastcpupid=0x1fffff) raw: 0017ffffc0000200 ffffea00044f1100
    dead000000000002 ffff88810004c780 raw: 0000000000000000 0000000000200020 00000001ffffffff 0000000000000000
    page dumped because: kasan: bad access detected Memory state around the buggy address: ffff88816912f280:
    fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc ffff88816912f300: fa fb fb fb fb fb fb fb fb fb fb fb fc
    fc fc fc >ffff88816912f380: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc ^ ffff88816912f400: fa fb fb
    fb fb fb fb fb fb fb fb fb fc fc fc fc ffff88816912f480: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc
    ================================================================== (CVE-2022-48913)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
