#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228659);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36901");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36901");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipv6: prevent NULL dereference in
    ip6_output() According to syzbot, there is a chance that ip6_dst_idev() returns NULL in ip6_output(). Most
    places in IPv6 stack deal with a NULL idev just fine, but not here. syzbot reported: general protection
    fault, probably for non-canonical address 0xdffffc00000000bc: 0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-
    ptr-deref in range [0x00000000000005e0-0x00000000000005e7] CPU: 0 PID: 9775 Comm: syz-executor.4 Not
    tainted 6.9.0-rc5-syzkaller-00157-g6a30653b604a #0 Hardware name: Google Google Compute Engine/Google
    Compute Engine, BIOS Google 03/27/2024 RIP: 0010:ip6_output+0x231/0x3f0 net/ipv6/ip6_output.c:237 Code: 3c
    1e 00 49 89 df 74 08 4c 89 ef e8 19 58 db f7 48 8b 44 24 20 49 89 45 00 49 89 c5 48 8d 9d e0 05 00 00 48
    89 d8 48 c1 e8 03 <42> 0f b6 04 38 84 c0 4c 8b 74 24 28 0f 85 61 01 00 00 8b 1b 31 ff RSP:
    0018:ffffc9000927f0d8 EFLAGS: 00010202 RAX: 00000000000000bc RBX: 00000000000005e0 RCX: 0000000000040000
    RDX: ffffc900131f9000 RSI: 0000000000004f47 RDI: 0000000000004f48 RBP: 0000000000000000 R08:
    ffffffff8a1f0b9a R09: 1ffffffff1f51fad R10: dffffc0000000000 R11: fffffbfff1f51fae R12: ffff8880293ec8c0
    R13: ffff88805d7fc000 R14: 1ffff1100527d91a R15: dffffc0000000000 FS: 00007f135c6856c0(0000)
    GS:ffff8880b9400000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    0000000020000080 CR3: 0000000064096000 CR4: 00000000003506f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    NF_HOOK include/linux/netfilter.h:314 [inline] ip6_xmit+0xefe/0x17f0 net/ipv6/ip6_output.c:358
    sctp_v6_xmit+0x9f2/0x13f0 net/sctp/ipv6.c:248 sctp_packet_transmit+0x26ad/0x2ca0 net/sctp/output.c:653
    sctp_packet_singleton+0x22c/0x320 net/sctp/outqueue.c:783 sctp_outq_flush_ctrl net/sctp/outqueue.c:914
    [inline] sctp_outq_flush+0x6d5/0x3e20 net/sctp/outqueue.c:1212 sctp_side_effects
    net/sctp/sm_sideeffect.c:1198 [inline] sctp_do_sm+0x59cc/0x60c0 net/sctp/sm_sideeffect.c:1169
    sctp_primitive_ASSOCIATE+0x95/0xc0 net/sctp/primitive.c:73 __sctp_connect+0x9cd/0xe30
    net/sctp/socket.c:1234 sctp_connect net/sctp/socket.c:4819 [inline] sctp_inet_connect+0x149/0x1f0
    net/sctp/socket.c:4834 __sys_connect_file net/socket.c:2048 [inline] __sys_connect+0x2df/0x310
    net/socket.c:2065 __do_sys_connect net/socket.c:2075 [inline] __se_sys_connect net/socket.c:2072 [inline]
    __x64_sys_connect+0x7a/0x90 net/socket.c:2072 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xf5/0x240 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f
    (CVE-2024-36901)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
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
