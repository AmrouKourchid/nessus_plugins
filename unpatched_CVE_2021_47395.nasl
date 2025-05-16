#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224358);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47395");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47395");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mac80211: limit injected vht mcs/nss
    in ieee80211_parse_tx_radiotap Limit max values for vht mcs and nss in ieee80211_parse_tx_radiotap routine
    in order to fix the following warning reported by syzbot: WARNING: CPU: 0 PID: 10717 at
    include/net/mac80211.h:989 ieee80211_rate_set_vht include/net/mac80211.h:989 [inline] WARNING: CPU: 0 PID:
    10717 at include/net/mac80211.h:989 ieee80211_parse_tx_radiotap+0x101e/0x12d0 net/mac80211/tx.c:2244
    Modules linked in: CPU: 0 PID: 10717 Comm: syz-executor.5 Not tainted 5.14.0-syzkaller #0 Hardware name:
    Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011 RIP:
    0010:ieee80211_rate_set_vht include/net/mac80211.h:989 [inline] RIP:
    0010:ieee80211_parse_tx_radiotap+0x101e/0x12d0 net/mac80211/tx.c:2244 RSP: 0018:ffffc9000186f3e8 EFLAGS:
    00010216 RAX: 0000000000000618 RBX: ffff88804ef76500 RCX: ffffc900143a5000 RDX: 0000000000040000 RSI:
    ffffffff888f478e RDI: 0000000000000003 RBP: 00000000ffffffff R08: 0000000000000000 R09: 0000000000000100
    R10: ffffffff888f46f9 R11: 0000000000000000 R12: 00000000fffffff8 R13: ffff88804ef7653c R14:
    0000000000000001 R15: 0000000000000004 FS: 00007fbf5718f700(0000) GS:ffff8880b9c00000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000001b2de23000 CR3:
    000000006a671000 CR4: 00000000001506f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
    DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000600 Call Trace:
    ieee80211_monitor_select_queue+0xa6/0x250 net/mac80211/iface.c:740 netdev_core_pick_tx+0x169/0x2e0
    net/core/dev.c:4089 __dev_queue_xmit+0x6f9/0x3710 net/core/dev.c:4165 __bpf_tx_skb net/core/filter.c:2114
    [inline] __bpf_redirect_no_mac net/core/filter.c:2139 [inline] __bpf_redirect+0x5ba/0xd20
    net/core/filter.c:2162 ____bpf_clone_redirect net/core/filter.c:2429 [inline]
    bpf_clone_redirect+0x2ae/0x420 net/core/filter.c:2401 bpf_prog_eeb6f53a69e5c6a2+0x59/0x234
    bpf_dispatcher_nop_func include/linux/bpf.h:717 [inline] __bpf_prog_run include/linux/filter.h:624
    [inline] bpf_prog_run include/linux/filter.h:631 [inline] bpf_test_run+0x381/0xa30 net/bpf/test_run.c:119
    bpf_prog_test_run_skb+0xb84/0x1ee0 net/bpf/test_run.c:663 bpf_prog_test_run kernel/bpf/syscall.c:3307
    [inline] __sys_bpf+0x2137/0x5df0 kernel/bpf/syscall.c:4605 __do_sys_bpf kernel/bpf/syscall.c:4691 [inline]
    __se_sys_bpf kernel/bpf/syscall.c:4689 [inline] __x64_sys_bpf+0x75/0xb0 kernel/bpf/syscall.c:4689
    do_syscall_x64 arch/x86/entry/common.c:50 [inline] do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x4665f9 (CVE-2021-47395)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47395");

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
