#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225745);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48912");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48912");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: fix use-after-free in
    __nf_register_net_hook() We must not dereference @new_hooks after nf_hook_mutex has been released, because
    other threads might have freed our allocated hooks already. BUG: KASAN: use-after-free in
    nf_hook_entries_get_hook_ops include/linux/netfilter.h:130 [inline] BUG: KASAN: use-after-free in
    hooks_validate net/netfilter/core.c:171 [inline] BUG: KASAN: use-after-free in
    __nf_register_net_hook+0x77a/0x820 net/netfilter/core.c:438 Read of size 2 at addr ffff88801c1a8000 by
    task syz-executor237/4430 CPU: 1 PID: 4430 Comm: syz-executor237 Not tainted
    5.17.0-rc5-syzkaller-00306-g2293be58d6a1 #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 01/01/2011 Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline]
    dump_stack_lvl+0xcd/0x134 lib/dump_stack.c:106 print_address_description.constprop.0.cold+0x8d/0x336
    mm/kasan/report.c:255 __kasan_report mm/kasan/report.c:442 [inline] kasan_report.cold+0x83/0xdf
    mm/kasan/report.c:459 nf_hook_entries_get_hook_ops include/linux/netfilter.h:130 [inline] hooks_validate
    net/netfilter/core.c:171 [inline] __nf_register_net_hook+0x77a/0x820 net/netfilter/core.c:438
    nf_register_net_hook+0x114/0x170 net/netfilter/core.c:571 nf_register_net_hooks+0x59/0xc0
    net/netfilter/core.c:587 nf_synproxy_ipv6_init+0x85/0xe0 net/netfilter/nf_synproxy_core.c:1218
    synproxy_tg6_check+0x30d/0x560 net/ipv6/netfilter/ip6t_SYNPROXY.c:81 xt_check_target+0x26c/0x9e0
    net/netfilter/x_tables.c:1038 check_target net/ipv6/netfilter/ip6_tables.c:530 [inline]
    find_check_entry.constprop.0+0x7f1/0x9e0 net/ipv6/netfilter/ip6_tables.c:573 translate_table+0xc8b/0x1750
    net/ipv6/netfilter/ip6_tables.c:735 do_replace net/ipv6/netfilter/ip6_tables.c:1153 [inline]
    do_ip6t_set_ctl+0x56e/0xb90 net/ipv6/netfilter/ip6_tables.c:1639 nf_setsockopt+0x83/0xe0
    net/netfilter/nf_sockopt.c:101 ipv6_setsockopt+0x122/0x180 net/ipv6/ipv6_sockglue.c:1024
    rawv6_setsockopt+0xd3/0x6a0 net/ipv6/raw.c:1084 __sys_setsockopt+0x2db/0x610 net/socket.c:2180
    __do_sys_setsockopt net/socket.c:2191 [inline] __se_sys_setsockopt net/socket.c:2188 [inline]
    __x64_sys_setsockopt+0xba/0x150 net/socket.c:2188 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
    do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80 entry_SYSCALL_64_after_hwframe+0x44/0xae RIP:
    0033:0x7f65a1ace7d9 Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 71 15 00 00 90 48 89 f8 48 89 f7 48 89 d6 48
    89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89
    01 48 RSP: 002b:00007f65a1a7f308 EFLAGS: 00000246 ORIG_RAX: 0000000000000036 RAX: ffffffffffffffda RBX:
    0000000000000006 RCX: 00007f65a1ace7d9 RDX: 0000000000000040 RSI: 0000000000000029 RDI: 0000000000000003
    RBP: 00007f65a1b574c8 R08: 0000000000000001 R09: 0000000000000000 R10: 0000000020000000 R11:
    0000000000000246 R12: 00007f65a1b55130 R13: 00007f65a1b574c0 R14: 00007f65a1b24090 R15: 0000000000022000
    </TASK> The buggy address belongs to the page: page:ffffea0000706a00 refcount:0 mapcount:0
    mapping:0000000000000000 index:0x0 pfn:0x1c1a8 flags: 0xfff00000000000(node=0|zone=1|lastcpupid=0x7ff)
    raw: 00fff00000000000 ffffea0001c1b108 ffffea000046dd08 0000000000000000 raw: 0000000000000000
    0000000000000000 00000000ffffffff 0000000000000000 page dumped because: kasan: bad access detected
    page_owner tracks the page as freed page last allocated via order 2, migratetype Unmovable, gfp_mask
    0x52dc0(GFP_KERNEL|__GFP_NOWARN|__GFP_NORETRY|__GFP_COMP|__GFP_ZERO), pid 4430, ts 1061781545818, free_ts
    1061791488993 prep_new_page mm/page_alloc.c:2434 [inline] get_page_from_freelist+0xa72/0x2f50
    mm/page_alloc.c:4165 __alloc_pages+0x1b2/0x500 mm/page_alloc.c:5389 __alloc_pages_node
    include/linux/gfp.h:572 [inline] alloc_pages_node include/linux/gfp.h:595 [inline]
    kmalloc_large_node+0x62/0x130 mm/slub.c:4438 __kmalloc_node+0x35a/0x4a0 mm/slub. ---truncated---
    (CVE-2022-48912)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48912");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/05");
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
