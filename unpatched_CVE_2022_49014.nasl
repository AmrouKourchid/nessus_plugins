#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225421);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49014");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49014");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: tun: Fix use-after-free in
    tun_detach() syzbot reported use-after-free in tun_detach() [1]. This causes call trace like below:
    ================================================================== BUG: KASAN: use-after-free in
    notifier_call_chain+0x1ee/0x200 kernel/notifier.c:75 Read of size 8 at addr ffff88807324e2a8 by task syz-
    executor.0/3673 CPU: 0 PID: 3673 Comm: syz-executor.0 Not tainted 6.1.0-rc5-syzkaller-00044-gcc675d22e422
    #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 10/26/2022 Call Trace:
    <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0xd1/0x138 lib/dump_stack.c:106
    print_address_description mm/kasan/report.c:284 [inline] print_report+0x15e/0x461 mm/kasan/report.c:395
    kasan_report+0xbf/0x1f0 mm/kasan/report.c:495 notifier_call_chain+0x1ee/0x200 kernel/notifier.c:75
    call_netdevice_notifiers_info+0x86/0x130 net/core/dev.c:1942 call_netdevice_notifiers_extack
    net/core/dev.c:1983 [inline] call_netdevice_notifiers net/core/dev.c:1997 [inline] netdev_wait_allrefs_any
    net/core/dev.c:10237 [inline] netdev_run_todo+0xbc6/0x1100 net/core/dev.c:10351 tun_detach
    drivers/net/tun.c:704 [inline] tun_chr_close+0xe4/0x190 drivers/net/tun.c:3467 __fput+0x27c/0xa90
    fs/file_table.c:320 task_work_run+0x16f/0x270 kernel/task_work.c:179 exit_task_work
    include/linux/task_work.h:38 [inline] do_exit+0xb3d/0x2a30 kernel/exit.c:820 do_group_exit+0xd4/0x2a0
    kernel/exit.c:950 get_signal+0x21b1/0x2440 kernel/signal.c:2858 arch_do_signal_or_restart+0x86/0x2300
    arch/x86/kernel/signal.c:869 exit_to_user_mode_loop kernel/entry/common.c:168 [inline]
    exit_to_user_mode_prepare+0x15f/0x250 kernel/entry/common.c:203 __syscall_exit_to_user_mode_work
    kernel/entry/common.c:285 [inline] syscall_exit_to_user_mode+0x1d/0x50 kernel/entry/common.c:296
    do_syscall_64+0x46/0xb0 arch/x86/entry/common.c:86 entry_SYSCALL_64_after_hwframe+0x63/0xcd The cause of
    the issue is that sock_put() from __tun_detach() drops last reference count for struct net, and then
    notifier_call_chain() from netdev_state_change() accesses that struct net. This patch fixes the issue by
    calling sock_put() from tun_detach() after all necessary accesses for the struct net has done.
    (CVE-2022-49014)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
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
