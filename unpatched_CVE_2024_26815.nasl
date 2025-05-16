#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228260);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26815");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26815");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: taprio: proper
    TCA_TAPRIO_TC_ENTRY_INDEX check taprio_parse_tc_entry() is not correctly checking
    TCA_TAPRIO_TC_ENTRY_INDEX attribute: int tc; // Signed value tc =
    nla_get_u32(tb[TCA_TAPRIO_TC_ENTRY_INDEX]); if (tc >= TC_QOPT_MAX_QUEUE) { NL_SET_ERR_MSG_MOD(extack, TC
    entry index out of range); return -ERANGE; } syzbot reported that it could fed arbitary negative values:
    UBSAN: shift-out-of-bounds in net/sched/sch_taprio.c:1722:18 shift exponent -2147418108 is negative CPU: 0
    PID: 5066 Comm: syz-executor367 Not tainted 6.8.0-rc7-syzkaller-00136-gc8a5c731fd12 #0 Hardware name:
    Google Google Compute Engine/Google Compute Engine, BIOS Google 02/29/2024 Call Trace: <TASK> __dump_stack
    lib/dump_stack.c:88 [inline] dump_stack_lvl+0x1e7/0x2e0 lib/dump_stack.c:106 ubsan_epilogue
    lib/ubsan.c:217 [inline] __ubsan_handle_shift_out_of_bounds+0x3c7/0x420 lib/ubsan.c:386
    taprio_parse_tc_entry net/sched/sch_taprio.c:1722 [inline] taprio_parse_tc_entries
    net/sched/sch_taprio.c:1768 [inline] taprio_change+0xb87/0x57d0 net/sched/sch_taprio.c:1877
    taprio_init+0x9da/0xc80 net/sched/sch_taprio.c:2134 qdisc_create+0x9d4/0x1190 net/sched/sch_api.c:1355
    tc_modify_qdisc+0xa26/0x1e40 net/sched/sch_api.c:1776 rtnetlink_rcv_msg+0x885/0x1040
    net/core/rtnetlink.c:6617 netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2543 netlink_unicast_kernel
    net/netlink/af_netlink.c:1341 [inline] netlink_unicast+0x7ea/0x980 net/netlink/af_netlink.c:1367
    netlink_sendmsg+0xa3b/0xd70 net/netlink/af_netlink.c:1908 sock_sendmsg_nosec net/socket.c:730 [inline]
    __sock_sendmsg+0x221/0x270 net/socket.c:745 ____sys_sendmsg+0x525/0x7d0 net/socket.c:2584 ___sys_sendmsg
    net/socket.c:2638 [inline] __sys_sendmsg+0x2b0/0x3a0 net/socket.c:2667 do_syscall_64+0xf9/0x240
    entry_SYSCALL_64_after_hwframe+0x6f/0x77 RIP: 0033:0x7f1b2dea3759 Code: 48 83 c4 28 c3 e8 d7 19 00 00 0f
    1f 80 00 00 00 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007ffd4de452f8 EFLAGS: 00000246
    ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX: 00007f1b2def0390 RCX: 00007f1b2dea3759 RDX:
    0000000000000000 RSI: 00000000200007c0 RDI: 0000000000000004 RBP: 0000000000000003 R08: 0000555500000000
    R09: 0000555500000000 R10: 0000555500000000 R11: 0000000000000246 R12: 00007ffd4de45340 R13:
    00007ffd4de45310 R14: 0000000000000001 R15: 00007ffd4de45340 (CVE-2024-26815)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26815");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
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
