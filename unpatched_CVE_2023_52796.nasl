#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226203);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52796");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52796");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipvlan: add ipvlan_route_v6_outbound()
    helper Inspired by syzbot reports using a stack of multiple ipvlan devices. Reduce stack size needed in
    ipvlan_process_v6_outbound() by moving the flowi6 struct used for the route lookup in an non inlined
    helper. ipvlan_route_v6_outbound() needs 120 bytes on the stack, immediately reclaimed. Also make sure
    ipvlan_process_v4_outbound() is not inlined. We might also have to lower MAX_NEST_DEV, because only syzbot
    uses setups with more than four stacked devices. BUG: TASK stack guard page was hit at ffffc9000e803ff8
    (stack is ffffc9000e804000..ffffc9000e808000) stack guard page: 0000 [#1] SMP KASAN CPU: 0 PID: 13442
    Comm: syz-executor.4 Not tainted 6.1.52-syzkaller #0 Hardware name: Google Google Compute Engine/Google
    Compute Engine, BIOS Google 10/09/2023 RIP: 0010:kasan_check_range+0x4/0x2a0 mm/kasan/generic.c:188 Code:
    48 01 c6 48 89 c7 e8 db 4e c1 03 31 c0 5d c3 cc 0f 0b eb 02 0f 0b b8 ea ff ff ff 5d c3 cc 00 00 cc cc 00
    00 cc cc 55 48 89 e5 <41> 57 41 56 41 55 41 54 53 b0 01 48 85 f6 0f 84 a4 01 00 00 48 89 RSP:
    0018:ffffc9000e804000 EFLAGS: 00010246 RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffffffff817e5bf2
    RDX: 0000000000000000 RSI: 0000000000000008 RDI: ffffffff887c6568 RBP: ffffc9000e804000 R08:
    0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: dffffc0000000001 R12: 1ffff92001d0080c
    R13: dffffc0000000000 R14: ffffffff87e6b100 R15: 0000000000000000 FS: 00007fd0c55826c0(0000)
    GS:ffff8881f6800000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    ffffc9000e803ff8 CR3: 0000000170ef7000 CR4: 00000000003506f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <#DF>
    </#DF> <TASK> [<ffffffff81f281d1>] __kasan_check_read+0x11/0x20 mm/kasan/shadow.c:31 [<ffffffff817e5bf2>]
    instrument_atomic_read include/linux/instrumented.h:72 [inline] [<ffffffff817e5bf2>] _test_bit
    include/asm-generic/bitops/instrumented-non-atomic.h:141 [inline] [<ffffffff817e5bf2>] cpumask_test_cpu
    include/linux/cpumask.h:506 [inline] [<ffffffff817e5bf2>] cpu_online include/linux/cpumask.h:1092 [inline]
    [<ffffffff817e5bf2>] trace_lock_acquire include/trace/events/lock.h:24 [inline] [<ffffffff817e5bf2>]
    lock_acquire+0xe2/0x590 kernel/locking/lockdep.c:5632 [<ffffffff8563221e>] rcu_lock_acquire+0x2e/0x40
    include/linux/rcupdate.h:306 [<ffffffff8561464d>] rcu_read_lock include/linux/rcupdate.h:747 [inline]
    [<ffffffff8561464d>] ip6_pol_route+0x15d/0x1440 net/ipv6/route.c:2221 [<ffffffff85618120>]
    ip6_pol_route_output+0x50/0x80 net/ipv6/route.c:2606 [<ffffffff856f65b5>] pol_lookup_func
    include/net/ip6_fib.h:584 [inline] [<ffffffff856f65b5>] fib6_rule_lookup+0x265/0x620
    net/ipv6/fib6_rules.c:116 [<ffffffff85618009>] ip6_route_output_flags_noref+0x2d9/0x3a0
    net/ipv6/route.c:2638 [<ffffffff8561821a>] ip6_route_output_flags+0xca/0x340 net/ipv6/route.c:2651
    [<ffffffff838bd5a3>] ip6_route_output include/net/ip6_route.h:100 [inline] [<ffffffff838bd5a3>]
    ipvlan_process_v6_outbound drivers/net/ipvlan/ipvlan_core.c:473 [inline] [<ffffffff838bd5a3>]
    ipvlan_process_outbound drivers/net/ipvlan/ipvlan_core.c:529 [inline] [<ffffffff838bd5a3>]
    ipvlan_xmit_mode_l3 drivers/net/ipvlan/ipvlan_core.c:602 [inline] [<ffffffff838bd5a3>]
    ipvlan_queue_xmit+0xc33/0x1be0 drivers/net/ipvlan/ipvlan_core.c:677 [<ffffffff838c2909>]
    ipvlan_start_xmit+0x49/0x100 drivers/net/ipvlan/ipvlan_main.c:229 [<ffffffff84d03900>] netdev_start_xmit
    include/linux/netdevice.h:4966 [inline] [<ffffffff84d03900>] xmit_one net/core/dev.c:3644 [inline]
    [<ffffffff84d03900>] dev_hard_start_xmit+0x320/0x980 net/core/dev.c:3660 [<ffffffff84d080e2>]
    __dev_queue_xmit+0x16b2/0x3370 net/core/dev.c:4324 [<ffffffff855ce4cd>] dev_queue_xmit
    include/linux/netdevice.h:3067 [inline] [<ffffffff855ce4cd>] neigh_hh_output include/net/neighbour.h:529
    [inline] [<f ---truncated--- (CVE-2023-52796)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52796");

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
