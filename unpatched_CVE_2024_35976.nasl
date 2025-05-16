#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229381);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35976");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35976");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: xsk: validate user input for
    XDP_{UMEM|COMPLETION}_FILL_RING syzbot reported an illegal copy in xsk_setsockopt() [1] Make sure to
    validate setsockopt() @optlen parameter. [1] BUG: KASAN: slab-out-of-bounds in copy_from_sockptr_offset
    include/linux/sockptr.h:49 [inline] BUG: KASAN: slab-out-of-bounds in copy_from_sockptr
    include/linux/sockptr.h:55 [inline] BUG: KASAN: slab-out-of-bounds in xsk_setsockopt+0x909/0xa40
    net/xdp/xsk.c:1420 Read of size 4 at addr ffff888028c6cde3 by task syz-executor.0/7549 CPU: 0 PID: 7549
    Comm: syz-executor.0 Not tainted 6.8.0-syzkaller-08951-gfe46a7dd189e #0 Hardware name: Google Google
    Compute Engine/Google Compute Engine, BIOS Google 03/27/2024 Call Trace: <TASK> __dump_stack
    lib/dump_stack.c:88 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:114 print_address_description
    mm/kasan/report.c:377 [inline] print_report+0x169/0x550 mm/kasan/report.c:488 kasan_report+0x143/0x180
    mm/kasan/report.c:601 copy_from_sockptr_offset include/linux/sockptr.h:49 [inline] copy_from_sockptr
    include/linux/sockptr.h:55 [inline] xsk_setsockopt+0x909/0xa40 net/xdp/xsk.c:1420
    do_sock_setsockopt+0x3af/0x720 net/socket.c:2311 __sys_setsockopt+0x1ae/0x250 net/socket.c:2334
    __do_sys_setsockopt net/socket.c:2343 [inline] __se_sys_setsockopt net/socket.c:2340 [inline]
    __x64_sys_setsockopt+0xb5/0xd0 net/socket.c:2340 do_syscall_64+0xfb/0x240
    entry_SYSCALL_64_after_hwframe+0x6d/0x75 RIP: 0033:0x7fb40587de69 Code: 28 00 00 00 75 05 48 83 c4 28 c3
    e8 e1 20 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007fb40665a0c8 EFLAGS: 00000246
    ORIG_RAX: 0000000000000036 RAX: ffffffffffffffda RBX: 00007fb4059abf80 RCX: 00007fb40587de69 RDX:
    0000000000000005 RSI: 000000000000011b RDI: 0000000000000006 RBP: 00007fb4058ca47a R08: 0000000000000002
    R09: 0000000000000000 R10: 0000000020001980 R11: 0000000000000246 R12: 0000000000000000 R13:
    000000000000000b R14: 00007fb4059abf80 R15: 00007fff57ee4d08 </TASK> Allocated by task 7549:
    kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68
    poison_kmalloc_redzone mm/kasan/common.c:370 [inline] __kasan_kmalloc+0x98/0xb0 mm/kasan/common.c:387
    kasan_kmalloc include/linux/kasan.h:211 [inline] __do_kmalloc_node mm/slub.c:3966 [inline]
    __kmalloc+0x233/0x4a0 mm/slub.c:3979 kmalloc include/linux/slab.h:632 [inline]
    __cgroup_bpf_run_filter_setsockopt+0xd2f/0x1040 kernel/bpf/cgroup.c:1869 do_sock_setsockopt+0x6b4/0x720
    net/socket.c:2293 __sys_setsockopt+0x1ae/0x250 net/socket.c:2334 __do_sys_setsockopt net/socket.c:2343
    [inline] __se_sys_setsockopt net/socket.c:2340 [inline] __x64_sys_setsockopt+0xb5/0xd0 net/socket.c:2340
    do_syscall_64+0xfb/0x240 entry_SYSCALL_64_after_hwframe+0x6d/0x75 The buggy address belongs to the object
    at ffff888028c6cde0 which belongs to the cache kmalloc-8 of size 8 The buggy address is located 1 bytes to
    the right of allocated 2-byte region [ffff888028c6cde0, ffff888028c6cde2) The buggy address belongs to the
    physical page: page:ffffea0000a31b00 refcount:1 mapcount:0 mapping:0000000000000000
    index:0xffff888028c6c9c0 pfn:0x28c6c anon flags: 0xfff00000000800(slab|node=0|zone=1|lastcpupid=0x7ff)
    page_type: 0xffffffff() raw: 00fff00000000800 ffff888014c41280 0000000000000000 dead000000000001 raw:
    ffff888028c6c9c0 0000000080800057 00000001ffffffff 0000000000000000 page dumped because: kasan: bad access
    detected page_owner tracks the page as allocated page last allocated via order 0, migratetype Unmovable,
    gfp_mask 0x112cc0(GFP_USER|__GFP_NOWARN|__GFP_NORETRY), pid 6648, tgid 6644 (syz-executor.0), ts
    133906047828, free_ts 133859922223 set_page_owner include/linux/page_owner.h:31 [inline]
    post_alloc_hook+0x1ea/0x210 mm/page_alloc.c:1533 prep_new_page mm/page_alloc.c: ---truncated---
    (CVE-2024-35976)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35976");

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
