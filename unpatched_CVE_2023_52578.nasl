#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226928);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52578");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52578");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: bridge: use DEV_STATS_INC()
    syzbot/KCSAN reported data-races in br_handle_frame_finish() [1] This function can run from multiple cpus
    without mutual exclusion. Adopt SMP safe DEV_STATS_INC() to update dev->stats fields. Handles updates to
    dev->stats.tx_dropped while we are at it. [1] BUG: KCSAN: data-race in br_handle_frame_finish /
    br_handle_frame_finish read-write to 0xffff8881374b2178 of 8 bytes by interrupt on cpu 1:
    br_handle_frame_finish+0xd4f/0xef0 net/bridge/br_input.c:189 br_nf_hook_thresh+0x1ed/0x220
    br_nf_pre_routing_finish_ipv6+0x50f/0x540 NF_HOOK include/linux/netfilter.h:304 [inline]
    br_nf_pre_routing_ipv6+0x1e3/0x2a0 net/bridge/br_netfilter_ipv6.c:178 br_nf_pre_routing+0x526/0xba0
    net/bridge/br_netfilter_hooks.c:508 nf_hook_entry_hookfn include/linux/netfilter.h:144 [inline]
    nf_hook_bridge_pre net/bridge/br_input.c:272 [inline] br_handle_frame+0x4c9/0x940
    net/bridge/br_input.c:417 __netif_receive_skb_core+0xa8a/0x21e0 net/core/dev.c:5417
    __netif_receive_skb_one_core net/core/dev.c:5521 [inline] __netif_receive_skb+0x57/0x1b0
    net/core/dev.c:5637 process_backlog+0x21f/0x380 net/core/dev.c:5965 __napi_poll+0x60/0x3b0
    net/core/dev.c:6527 napi_poll net/core/dev.c:6594 [inline] net_rx_action+0x32b/0x750 net/core/dev.c:6727
    __do_softirq+0xc1/0x265 kernel/softirq.c:553 run_ksoftirqd+0x17/0x20 kernel/softirq.c:921
    smpboot_thread_fn+0x30a/0x4a0 kernel/smpboot.c:164 kthread+0x1d7/0x210 kernel/kthread.c:388
    ret_from_fork+0x48/0x60 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20
    arch/x86/entry/entry_64.S:304 read-write to 0xffff8881374b2178 of 8 bytes by interrupt on cpu 0:
    br_handle_frame_finish+0xd4f/0xef0 net/bridge/br_input.c:189 br_nf_hook_thresh+0x1ed/0x220
    br_nf_pre_routing_finish_ipv6+0x50f/0x540 NF_HOOK include/linux/netfilter.h:304 [inline]
    br_nf_pre_routing_ipv6+0x1e3/0x2a0 net/bridge/br_netfilter_ipv6.c:178 br_nf_pre_routing+0x526/0xba0
    net/bridge/br_netfilter_hooks.c:508 nf_hook_entry_hookfn include/linux/netfilter.h:144 [inline]
    nf_hook_bridge_pre net/bridge/br_input.c:272 [inline] br_handle_frame+0x4c9/0x940
    net/bridge/br_input.c:417 __netif_receive_skb_core+0xa8a/0x21e0 net/core/dev.c:5417
    __netif_receive_skb_one_core net/core/dev.c:5521 [inline] __netif_receive_skb+0x57/0x1b0
    net/core/dev.c:5637 process_backlog+0x21f/0x380 net/core/dev.c:5965 __napi_poll+0x60/0x3b0
    net/core/dev.c:6527 napi_poll net/core/dev.c:6594 [inline] net_rx_action+0x32b/0x750 net/core/dev.c:6727
    __do_softirq+0xc1/0x265 kernel/softirq.c:553 do_softirq+0x5e/0x90 kernel/softirq.c:454
    __local_bh_enable_ip+0x64/0x70 kernel/softirq.c:381 __raw_spin_unlock_bh
    include/linux/spinlock_api_smp.h:167 [inline] _raw_spin_unlock_bh+0x36/0x40 kernel/locking/spinlock.c:210
    spin_unlock_bh include/linux/spinlock.h:396 [inline] batadv_tt_local_purge+0x1a8/0x1f0 net/batman-
    adv/translation-table.c:1356 batadv_tt_purge+0x2b/0x630 net/batman-adv/translation-table.c:3560
    process_one_work kernel/workqueue.c:2630 [inline] process_scheduled_works+0x5b8/0xa30
    kernel/workqueue.c:2703 worker_thread+0x525/0x730 kernel/workqueue.c:2784 kthread+0x1d7/0x210
    kernel/kthread.c:388 ret_from_fork+0x48/0x60 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20
    arch/x86/entry/entry_64.S:304 value changed: 0x00000000000d7190 -> 0x00000000000d7191 Reported by Kernel
    Concurrency Sanitizer on: CPU: 0 PID: 14848 Comm: kworker/u4:11 Not tainted
    6.6.0-rc1-syzkaller-00236-gad8a69f361b9 #0 (CVE-2023-52578)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52578");

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
