#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226292);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52782");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52782");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Track xmit submission to
    PTP WQ after populating metadata map Ensure the skb is available in metadata mapping to skbs before
    tracking the metadata index for detecting undelivered CQEs. If the metadata index is put in the tracking
    list before putting the skb in the map, the metadata index might be used for detecting undelivered CQEs
    before the relevant skb is available in the map, which can lead to a null-ptr-deref. Log: general
    protection fault, probably for non-canonical address 0xdffffc0000000005: 0000 [#1] SMP KASAN KASAN: null-
    ptr-deref in range [0x0000000000000028-0x000000000000002f] CPU: 0 PID: 1243 Comm: kworker/0:2 Not tainted
    6.6.0-rc4+ #108 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
    rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 Workqueue: events mlx5e_rx_dim_work [mlx5_core]
    RIP: 0010:mlx5e_ptp_napi_poll+0x9a4/0x2290 [mlx5_core] Code: 8c 24 38 cc ff ff 4c 8d 3c c1 4c 89 f9 48 c1
    e9 03 42 80 3c 31 00 0f 85 97 0f 00 00 4d 8b 3f 49 8d 7f 28 48 89 f9 48 c1 e9 03 <42> 80 3c 31 00 0f 85 8b
    0f 00 00 49 8b 47 28 48 85 c0 0f 84 05 07 RSP: 0018:ffff8884d3c09c88 EFLAGS: 00010206 RAX:
    0000000000000069 RBX: ffff8881160349d8 RCX: 0000000000000005 RDX: ffffed10218f48cf RSI: 0000000000000004
    RDI: 0000000000000028 RBP: ffff888122707700 R08: 0000000000000001 R09: ffffed109a781383 R10:
    0000000000000003 R11: 0000000000000003 R12: ffff88810c7a7a40 R13: ffff888122707700 R14: dffffc0000000000
    R15: 0000000000000000 FS: 0000000000000000(0000) GS:ffff8884d3c00000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f4f878dd6e0 CR3: 000000014d108002 CR4: 0000000000370eb0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <IRQ> ? die_addr+0x3c/0xa0 ?
    exc_general_protection+0x144/0x210 ? asm_exc_general_protection+0x22/0x30 ?
    mlx5e_ptp_napi_poll+0x9a4/0x2290 [mlx5_core] ? mlx5e_ptp_napi_poll+0x8f6/0x2290 [mlx5_core]
    __napi_poll.constprop.0+0xa4/0x580 net_rx_action+0x460/0xb80 ? _raw_spin_unlock_irqrestore+0x32/0x60 ?
    __napi_poll.constprop.0+0x580/0x580 ? tasklet_action_common.isra.0+0x2ef/0x760 __do_softirq+0x26c/0x827
    irq_exit_rcu+0xc2/0x100 common_interrupt+0x7f/0xa0 </IRQ> <TASK> asm_common_interrupt+0x22/0x40 RIP:
    0010:__kmem_cache_alloc_node+0xb/0x330 Code: 41 5d 41 5e 41 5f c3 8b 44 24 14 8b 4c 24 10 09 c8 eb d5 e8
    b7 43 ca 01 0f 1f 80 00 00 00 00 0f 1f 44 00 00 55 48 89 e5 41 57 <41> 56 41 89 d6 41 55 41 89 f5 41 54 49
    89 fc 53 48 83 e4 f0 48 83 RSP: 0018:ffff88812c4079c0 EFLAGS: 00000246 RAX: 1ffffffff083c7fe RBX:
    ffff888100042dc0 RCX: 0000000000000218 RDX: 00000000ffffffff RSI: 0000000000000dc0 RDI: ffff888100042dc0
    RBP: ffff88812c4079c8 R08: ffffffffa0289f96 R09: ffffed1025880ea9 R10: ffff888138839f80 R11:
    0000000000000002 R12: 0000000000000dc0 R13: 0000000000000100 R14: 000000000000008c R15: ffff8881271fc450 ?
    cmd_exec+0x796/0x2200 [mlx5_core] kmalloc_trace+0x26/0xc0 cmd_exec+0x796/0x2200 [mlx5_core]
    mlx5_cmd_do+0x22/0xc0 [mlx5_core] mlx5_cmd_exec+0x17/0x30 [mlx5_core]
    mlx5_core_modify_cq_moderation+0x139/0x1b0 [mlx5_core] ? mlx5_add_cq_to_tasklet+0x280/0x280 [mlx5_core] ?
    lockdep_set_lock_cmp_fn+0x190/0x190 ? process_one_work+0x659/0x1220 mlx5e_rx_dim_work+0x9d/0x100
    [mlx5_core] process_one_work+0x730/0x1220 ? lockdep_hardirqs_on_prepare+0x400/0x400 ?
    max_active_store+0xf0/0xf0 ? assign_work+0x168/0x240 worker_thread+0x70f/0x12d0 ?
    __kthread_parkme+0xd1/0x1d0 ? process_one_work+0x1220/0x1220 kthread+0x2d9/0x3b0 ?
    kthread_complete_and_exit+0x20/0x20 ret_from_fork+0x2d/0x70 ? kthread_complete_and_exit+0x20/0x20
    ret_from_fork_as ---truncated--- (CVE-2023-52782)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52782");

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
