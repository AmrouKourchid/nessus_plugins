#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225566);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48810");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48810");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipmr,ip6mr: acquire RTNL before
    calling ip[6]mr_free_table() on failure path ip[6]mr_free_table() can only be called under RTNL lock.
    RTNL: assertion failed at net/core/dev.c (10367) WARNING: CPU: 1 PID: 5890 at net/core/dev.c:10367
    unregister_netdevice_many+0x1246/0x1850 net/core/dev.c:10367 Modules linked in: CPU: 1 PID: 5890 Comm:
    syz-executor.2 Not tainted 5.16.0-syzkaller-11627-g422ee58dc0ef #0 Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 01/01/2011 RIP: 0010:unregister_netdevice_many+0x1246/0x1850
    net/core/dev.c:10367 Code: 0f 85 9b ee ff ff e8 69 07 4b fa ba 7f 28 00 00 48 c7 c6 00 90 ae 8a 48 c7 c7
    40 90 ae 8a c6 05 6d b1 51 06 01 e8 8c 90 d8 01 <0f> 0b e9 70 ee ff ff e8 3e 07 4b fa 4c 89 e7 e8 86 2a 59
    fa e9 ee RSP: 0018:ffffc900046ff6e0 EFLAGS: 00010286 RAX: 0000000000000000 RBX: 0000000000000000 RCX:
    0000000000000000 RDX: ffff888050f51d00 RSI: ffffffff815fa008 RDI: fffff520008dfece RBP: 0000000000000000
    R08: 0000000000000000 R09: 0000000000000000 R10: ffffffff815f3d6e R11: 0000000000000000 R12:
    00000000fffffff4 R13: dffffc0000000000 R14: ffffc900046ff750 R15: ffff88807b7dc000 FS:
    00007f4ab736e700(0000) GS:ffff8880b9d00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 00007fee0b4f8990 CR3: 000000001e7d2000 CR4: 00000000003506e0 DR0: 0000000000000000
    DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
    0000000000000400 Call Trace: <TASK> mroute_clean_tables+0x244/0xb40 net/ipv6/ip6mr.c:1509 ip6mr_free_table
    net/ipv6/ip6mr.c:389 [inline] ip6mr_rules_init net/ipv6/ip6mr.c:246 [inline] ip6mr_net_init
    net/ipv6/ip6mr.c:1306 [inline] ip6mr_net_init+0x3f0/0x4e0 net/ipv6/ip6mr.c:1298 ops_init+0xaf/0x470
    net/core/net_namespace.c:140 setup_net+0x54f/0xbb0 net/core/net_namespace.c:331 copy_net_ns+0x318/0x760
    net/core/net_namespace.c:475 create_new_namespaces+0x3f6/0xb20 kernel/nsproxy.c:110
    copy_namespaces+0x391/0x450 kernel/nsproxy.c:178 copy_process+0x2e0c/0x7300 kernel/fork.c:2167
    kernel_clone+0xe7/0xab0 kernel/fork.c:2555 __do_sys_clone+0xc8/0x110 kernel/fork.c:2672 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x7f4ab89f9059 Code: Unable to access opcode bytes at
    RIP 0x7f4ab89f902f. RSP: 002b:00007f4ab736e118 EFLAGS: 00000206 ORIG_RAX: 0000000000000038 RAX:
    ffffffffffffffda RBX: 00007f4ab8b0bf60 RCX: 00007f4ab89f9059 RDX: 0000000020000280 RSI: 0000000020000270
    RDI: 0000000040200000 RBP: 00007f4ab8a5308d R08: 0000000020000300 R09: 0000000020000300 R10:
    00000000200002c0 R11: 0000000000000206 R12: 0000000000000000 R13: 00007ffc3977cc1f R14: 00007f4ab736e300
    R15: 0000000000022000 </TASK> (CVE-2022-48810)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
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
