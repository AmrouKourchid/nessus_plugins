#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225706);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48781");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48781");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: crypto: af_alg - get rid of
    alg_memory_allocated alg_memory_allocated does not seem to be really used. alg_proto does have a
    .memory_allocated field, but no corresponding .sysctl_mem. This means sk_has_account() returns true, but
    all sk_prot_mem_limits() users will trigger a NULL dereference [1]. THis was not a problem until
    SO_RESERVE_MEM addition. general protection fault, probably for non-canonical address 0xdffffc0000000001:
    0000 [#1] PREEMPT SMP KASAN KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f] CPU: 1
    PID: 3591 Comm: syz-executor153 Not tainted 5.17.0-rc3-syzkaller-00316-gb81b1829e7e3 #0 Hardware name:
    Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011 RIP: 0010:sk_prot_mem_limits
    include/net/sock.h:1523 [inline] RIP: 0010:sock_reserve_memory+0x1d7/0x330 net/core/sock.c:1000 Code: 08
    00 74 08 48 89 ef e8 27 20 bb f9 4c 03 7c 24 10 48 8b 6d 00 48 83 c5 08 48 89 e8 48 c1 e8 03 48 b9 00 00
    00 00 00 fc ff df <80> 3c 08 00 74 08 48 89 ef e8 fb 1f bb f9 48 8b 6d 00 4c 89 ff 48 RSP:
    0018:ffffc90001f1fb68 EFLAGS: 00010202 RAX: 0000000000000001 RBX: ffff88814aabc000 RCX: dffffc0000000000
    RDX: 0000000000000001 RSI: 0000000000000008 RDI: ffffffff90e18120 RBP: 0000000000000008 R08:
    dffffc0000000000 R09: fffffbfff21c3025 R10: fffffbfff21c3025 R11: 0000000000000000 R12: ffffffff8d109840
    R13: 0000000000001002 R14: 0000000000000001 R15: 0000000000000001 FS: 0000555556e08300(0000)
    GS:ffff8880b9b00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007fc74416f130 CR3: 0000000073d9e000 CR4: 00000000003506e0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    sock_setsockopt+0x14a9/0x3a30 net/core/sock.c:1446 __sys_setsockopt+0x5af/0x980 net/socket.c:2176
    __do_sys_setsockopt net/socket.c:2191 [inline] __se_sys_setsockopt net/socket.c:2188 [inline]
    __x64_sys_setsockopt+0xb1/0xc0 net/socket.c:2188 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
    do_syscall_64+0x44/0xd0 arch/x86/entry/common.c:80 entry_SYSCALL_64_after_hwframe+0x44/0xae RIP:
    0033:0x7fc7440fddc9 Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 51 15 00 00 90 48 89 f8 48 89 f7 48 89 d6 48
    89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 c0 ff ff ff f7 d8 64 89
    01 48 RSP: 002b:00007ffe98f07968 EFLAGS: 00000246 ORIG_RAX: 0000000000000036 RAX: ffffffffffffffda RBX:
    0000000000000003 RCX: 00007fc7440fddc9 RDX: 0000000000000049 RSI: 0000000000000001 RDI: 0000000000000004
    RBP: 0000000000000000 R08: 0000000000000004 R09: 00007ffe98f07990 R10: 0000000020000000 R11:
    0000000000000246 R12: 00007ffe98f0798c R13: 00007ffe98f079a0 R14: 00007ffe98f079e0 R15: 0000000000000000
    </TASK> Modules linked in: ---[ end trace 0000000000000000 ]--- RIP: 0010:sk_prot_mem_limits
    include/net/sock.h:1523 [inline] RIP: 0010:sock_reserve_memory+0x1d7/0x330 net/core/sock.c:1000 Code: 08
    00 74 08 48 89 ef e8 27 20 bb f9 4c 03 7c 24 10 48 8b 6d 00 48 83 c5 08 48 89 e8 48 c1 e8 03 48 b9 00 00
    00 00 00 fc ff df <80> 3c 08 00 74 08 48 89 ef e8 fb 1f bb f9 48 8b 6d 00 4c 89 ff 48 RSP:
    0018:ffffc90001f1fb68 EFLAGS: 00010202 RAX: 0000000000000001 RBX: ffff88814aabc000 RCX: dffffc0000000000
    RDX: 0000000000000001 RSI: 0000000000000008 RDI: ffffffff90e18120 RBP: 0000000000000008 R08:
    dffffc0000000000 R09: fffffbfff21c3025 R10: fffffbfff21c3025 R11: 0000000000000000 R12: ffffffff8d109840
    R13: 0000000000001002 R14: 0000000000000001 R15: 0000000000000001 FS: 0000555556e08300(0000)
    GS:ffff8880b9b00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007fc74416f130 CR3: 0000000073d9e000 CR4: 00000000003506e0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 (CVE-2022-48781)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48781");

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
