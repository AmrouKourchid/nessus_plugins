#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230169);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47419");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47419");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: sch_taprio: properly cancel
    timer from taprio_destroy() There is a comment in qdisc_create() about us not calling ops->reset() in some
    cases. err_out4: /* * Any broken qdiscs that would require a ops->reset() here? * The qdisc was never in
    action so it shouldn't be necessary. */ As taprio sets a timer before actually receiving a packet, we need
    to cancel it from ops->destroy, just in case ops->reset has not been called. syzbot reported: ODEBUG: free
    active (active state 0) object type: hrtimer hint: advance_sched+0x0/0x9a0
    arch/x86/include/asm/atomic64_64.h:22 WARNING: CPU: 0 PID: 8441 at lib/debugobjects.c:505
    debug_print_object+0x16e/0x250 lib/debugobjects.c:505 Modules linked in: CPU: 0 PID: 8441 Comm: syz-
    executor813 Not tainted 5.14.0-rc6-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 01/01/2011 RIP: 0010:debug_print_object+0x16e/0x250 lib/debugobjects.c:505 Code: ff df
    48 89 fa 48 c1 ea 03 80 3c 02 00 0f 85 af 00 00 00 48 8b 14 dd e0 d3 e3 89 4c 89 ee 48 c7 c7 e0 c7 e3 89
    e8 5b 86 11 05 <0f> 0b 83 05 85 03 92 09 01 48 83 c4 18 5b 5d 41 5c 41 5d 41 5e c3 RSP:
    0018:ffffc9000130f330 EFLAGS: 00010282 RAX: 0000000000000000 RBX: 0000000000000003 RCX: 0000000000000000
    RDX: ffff88802baeb880 RSI: ffffffff815d87b5 RDI: fffff52000261e58 RBP: 0000000000000001 R08:
    0000000000000000 R09: 0000000000000000 R10: ffffffff815d25ee R11: 0000000000000000 R12: ffffffff898dd020
    R13: ffffffff89e3ce20 R14: ffffffff81653630 R15: dffffc0000000000 FS: 0000000000f0d300(0000)
    GS:ffff8880b9d00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007ffb64b3e000 CR3: 0000000036557000 CR4: 00000000001506e0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace:
    __debug_check_no_obj_freed lib/debugobjects.c:987 [inline] debug_check_no_obj_freed+0x301/0x420
    lib/debugobjects.c:1018 slab_free_hook mm/slub.c:1603 [inline] slab_free_freelist_hook+0x171/0x240
    mm/slub.c:1653 slab_free mm/slub.c:3213 [inline] kfree+0xe4/0x540 mm/slub.c:4267 qdisc_create+0xbcf/0x1320
    net/sched/sch_api.c:1299 tc_modify_qdisc+0x4c8/0x1a60 net/sched/sch_api.c:1663
    rtnetlink_rcv_msg+0x413/0xb80 net/core/rtnetlink.c:5571 netlink_rcv_skb+0x153/0x420
    net/netlink/af_netlink.c:2504 netlink_unicast_kernel net/netlink/af_netlink.c:1314 [inline]
    netlink_unicast+0x533/0x7d0 net/netlink/af_netlink.c:1340 netlink_sendmsg+0x86d/0xdb0
    net/netlink/af_netlink.c:1929 sock_sendmsg_nosec net/socket.c:704 [inline] sock_sendmsg+0xcf/0x120
    net/socket.c:724 ____sys_sendmsg+0x6e8/0x810 net/socket.c:2403 ___sys_sendmsg+0xf3/0x170 net/socket.c:2457
    __sys_sendmsg+0xe5/0x1b0 net/socket.c:2486 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
    do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80 (CVE-2021-47419)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47419");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
        "os_version": "8"
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
