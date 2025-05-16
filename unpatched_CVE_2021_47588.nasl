#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224308);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47588");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47588");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: sit: do not call ipip6_dev_free() from
    sit_init_net() ipip6_dev_free is sit dev->priv_destructor, already called by register_netdevice() if
    something goes wrong. Alternative would be to make ipip6_dev_free() robust against multiple invocations,
    but other drivers do not implement this strategy. syzbot reported: dst_release underflow WARNING: CPU: 0
    PID: 5059 at net/core/dst.c:173 dst_release+0xd8/0xe0 net/core/dst.c:173 Modules linked in: CPU: 1 PID:
    5059 Comm: syz-executor.4 Not tainted 5.16.0-rc5-syzkaller #0 Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 01/01/2011 RIP: 0010:dst_release+0xd8/0xe0 net/core/dst.c:173
    Code: 4c 89 f2 89 d9 31 c0 5b 41 5e 5d e9 da d5 44 f9 e8 1d 90 5f f9 c6 05 87 48 c6 05 01 48 c7 c7 80 44
    99 8b 31 c0 e8 e8 67 29 f9 <0f> 0b eb 85 0f 1f 40 00 53 48 89 fb e8 f7 8f 5f f9 48 83 c3 a8 48 RSP:
    0018:ffffc9000aa5faa0 EFLAGS: 00010246 RAX: d6894a925dd15a00 RBX: 00000000ffffffff RCX: 0000000000040000
    RDX: ffffc90005e19000 RSI: 000000000003ffff RDI: 0000000000040000 RBP: 0000000000000000 R08:
    ffffffff816a1f42 R09: ffffed1017344f2c R10: ffffed1017344f2c R11: 0000000000000000 R12: 0000607f462b1358
    R13: 1ffffffff1bfd305 R14: ffffe8ffffcb1358 R15: dffffc0000000000 FS: 00007f66c71a2700(0000)
    GS:ffff8880b9a00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007f88aaed5058 CR3: 0000000023e0f000 CR4: 00000000003506f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    dst_cache_destroy+0x107/0x1e0 net/core/dst_cache.c:160 ipip6_dev_free net/ipv6/sit.c:1414 [inline]
    sit_init_net+0x229/0x550 net/ipv6/sit.c:1936 ops_init+0x313/0x430 net/core/net_namespace.c:140
    setup_net+0x35b/0x9d0 net/core/net_namespace.c:326 copy_net_ns+0x359/0x5c0 net/core/net_namespace.c:470
    create_new_namespaces+0x4ce/0xa00 kernel/nsproxy.c:110 unshare_nsproxy_namespaces+0x11e/0x180
    kernel/nsproxy.c:226 ksys_unshare+0x57d/0xb50 kernel/fork.c:3075 __do_sys_unshare kernel/fork.c:3146
    [inline] __se_sys_unshare kernel/fork.c:3144 [inline] __x64_sys_unshare+0x34/0x40 kernel/fork.c:3144
    do_syscall_x64 arch/x86/entry/common.c:50 [inline] do_syscall_64+0x44/0xd0 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x7f66c882ce99 Code: ff ff c3 66 2e 0f 1f 84 00 00 00
    00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007f66c71a2168 EFLAGS: 00000246
    ORIG_RAX: 0000000000000110 RAX: ffffffffffffffda RBX: 00007f66c893ff60 RCX: 00007f66c882ce99 RDX:
    0000000000000000 RSI: 0000000000000000 RDI: 0000000048040200 RBP: 00007f66c8886ff1 R08: 0000000000000000
    R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000 R13:
    00007fff6634832f R14: 00007f66c71a2300 R15: 0000000000022000 </TASK> (CVE-2021-47588)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47588");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
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
