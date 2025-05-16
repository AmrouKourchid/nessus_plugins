#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228439);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36902");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36902");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipv6: fib6_rules: avoid possible NULL
    dereference in fib6_rule_action() syzbot is able to trigger the following crash [1], caused by unsafe
    ip6_dst_idev() use. Indeed ip6_dst_idev() can return NULL, and must always be checked. [1] Oops: general
    protection fault, probably for non-canonical address 0xdffffc0000000000: 0000 [#1] PREEMPT SMP KASAN PTI
    KASAN: null-ptr-deref in range [0x0000000000000000-0x0000000000000007] CPU: 0 PID: 31648 Comm: syz-
    executor.0 Not tainted 6.9.0-rc4-next-20240417-syzkaller #0 Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 03/27/2024 RIP: 0010:__fib6_rule_action
    net/ipv6/fib6_rules.c:237 [inline] RIP: 0010:fib6_rule_action+0x241/0x7b0 net/ipv6/fib6_rules.c:267 Code:
    02 00 00 49 8d 9f d8 00 00 00 48 89 d8 48 c1 e8 03 42 80 3c 20 00 74 08 48 89 df e8 f9 32 bf f7 48 8b 1b
    48 89 d8 48 c1 e8 03 <42> 80 3c 20 00 74 08 48 89 df e8 e0 32 bf f7 4c 8b 03 48 89 ef 4c RSP:
    0018:ffffc9000fc1f2f0 EFLAGS: 00010246 RAX: 0000000000000000 RBX: 0000000000000000 RCX: 1a772f98c8186700
    RDX: 0000000000000003 RSI: ffffffff8bcac4e0 RDI: ffffffff8c1f9760 RBP: ffff8880673fb980 R08:
    ffffffff8fac15ef R09: 1ffffffff1f582bd R10: dffffc0000000000 R11: fffffbfff1f582be R12: dffffc0000000000
    R13: 0000000000000080 R14: ffff888076509000 R15: ffff88807a029a00 FS: 00007f55e82ca6c0(0000)
    GS:ffff8880b9400000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    0000001b31d23000 CR3: 0000000022b66000 CR4: 00000000003506f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    fib_rules_lookup+0x62c/0xdb0 net/core/fib_rules.c:317 fib6_rule_lookup+0x1fd/0x790
    net/ipv6/fib6_rules.c:108 ip6_route_output_flags_noref net/ipv6/route.c:2637 [inline]
    ip6_route_output_flags+0x38e/0x610 net/ipv6/route.c:2649 ip6_route_output include/net/ip6_route.h:93
    [inline] ip6_dst_lookup_tail+0x189/0x11a0 net/ipv6/ip6_output.c:1120 ip6_dst_lookup_flow+0xb9/0x180
    net/ipv6/ip6_output.c:1250 sctp_v6_get_dst+0x792/0x1e20 net/sctp/ipv6.c:326
    sctp_transport_route+0x12c/0x2e0 net/sctp/transport.c:455 sctp_assoc_add_peer+0x614/0x15c0
    net/sctp/associola.c:662 sctp_connect_new_asoc+0x31d/0x6c0 net/sctp/socket.c:1099
    __sctp_connect+0x66d/0xe30 net/sctp/socket.c:1197 sctp_connect net/sctp/socket.c:4819 [inline]
    sctp_inet_connect+0x149/0x1f0 net/sctp/socket.c:4834 __sys_connect_file net/socket.c:2048 [inline]
    __sys_connect+0x2df/0x310 net/socket.c:2065 __do_sys_connect net/socket.c:2075 [inline] __se_sys_connect
    net/socket.c:2072 [inline] __x64_sys_connect+0x7a/0x90 net/socket.c:2072 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf5/0x240 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f (CVE-2024-36902)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/23");
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
