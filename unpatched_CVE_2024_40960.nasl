#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228448);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40960");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40960");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipv6: prevent possible NULL
    dereference in rt6_probe() syzbot caught a NULL dereference in rt6_probe() [1] Bail out if __in6_dev_get()
    returns NULL. [1] Oops: general protection fault, probably for non-canonical address 0xdffffc00000000cb:
    0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range [0x0000000000000658-0x000000000000065f]
    CPU: 1 PID: 22444 Comm: syz-executor.0 Not tainted 6.10.0-rc2-syzkaller-00383-gb8481381d4e2 #0 Hardware
    name: Google Google Compute Engine/Google Compute Engine, BIOS Google 04/02/2024 RIP: 0010:rt6_probe
    net/ipv6/route.c:656 [inline] RIP: 0010:find_match+0x8c4/0xf50 net/ipv6/route.c:758 Code: 14 fd f7 48 8b
    85 38 ff ff ff 48 c7 45 b0 00 00 00 00 48 8d b8 5c 06 00 00 48 b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1
    ea 03 <0f> b6 14 02 48 89 f8 83 e0 07 83 c0 03 38 d0 7c 08 84 d2 0f 85 19 RSP: 0018:ffffc900034af070
    EFLAGS: 00010203 RAX: dffffc0000000000 RBX: 0000000000000000 RCX: ffffc90004521000 RDX: 00000000000000cb
    RSI: ffffffff8990d0cd RDI: 000000000000065c RBP: ffffc900034af150 R08: 0000000000000005 R09:
    0000000000000000 R10: 0000000000000001 R11: 0000000000000002 R12: 000000000000000a R13: 1ffff92000695e18
    R14: ffff8880244a1d20 R15: 0000000000000000 FS: 00007f4844a5a6c0(0000) GS:ffff8880b9300000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000001b31b27000 CR3:
    000000002d42c000 CR4: 00000000003506f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
    DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    rt6_nh_find_match+0xfa/0x1a0 net/ipv6/route.c:784 nexthop_for_each_fib6_nh+0x26d/0x4a0
    net/ipv4/nexthop.c:1496 __find_rr_leaf+0x6e7/0xe00 net/ipv6/route.c:825 find_rr_leaf net/ipv6/route.c:853
    [inline] rt6_select net/ipv6/route.c:897 [inline] fib6_table_lookup+0x57e/0xa30 net/ipv6/route.c:2195
    ip6_pol_route+0x1cd/0x1150 net/ipv6/route.c:2231 pol_lookup_func include/net/ip6_fib.h:616 [inline]
    fib6_rule_lookup+0x386/0x720 net/ipv6/fib6_rules.c:121 ip6_route_output_flags_noref net/ipv6/route.c:2639
    [inline] ip6_route_output_flags+0x1d0/0x640 net/ipv6/route.c:2651
    ip6_dst_lookup_tail.constprop.0+0x961/0x1760 net/ipv6/ip6_output.c:1147 ip6_dst_lookup_flow+0x99/0x1d0
    net/ipv6/ip6_output.c:1250 rawv6_sendmsg+0xdab/0x4340 net/ipv6/raw.c:898 inet_sendmsg+0x119/0x140
    net/ipv4/af_inet.c:853 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745
    [inline] sock_write_iter+0x4b8/0x5c0 net/socket.c:1160 new_sync_write fs/read_write.c:497 [inline]
    vfs_write+0x6b6/0x1140 fs/read_write.c:590 ksys_write+0x1f8/0x260 fs/read_write.c:643 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f (CVE-2024-40960)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40960");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
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
