#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225719);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49238");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49238");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ath11k: free peer for station when
    disconnect from AP for QCA6390/WCN6855 Commit b4a0f54156ac (ath11k: move peer delete after vdev stop of
    station for QCA6390 and WCN6855) is to fix firmware crash by changing the WMI command sequence, but
    actually skip all the peer delete operation, then it lead commit 58595c9874c6 (ath11k: Fixing dangling
    pointer issue upon peer delete failure) not take effect, and then happened a use-after-free warning from
    KASAN. because the peer->sta is not set to NULL and then used later. Change to only skip the
    WMI_PEER_DELETE_CMDID for QCA6390/WCN6855. log of user-after-free: [ 534.888665] BUG: KASAN: use-after-
    free in ath11k_dp_rx_update_peer_stats+0x912/0xc10 [ath11k] [ 534.888696] Read of size 8 at addr
    ffff8881396bb1b8 by task rtcwake/2860 [ 534.888705] CPU: 4 PID: 2860 Comm: rtcwake Kdump: loaded Tainted:
    G W 5.15.0-wt-ath+ #523 [ 534.888712] Hardware name: Intel(R) Client Systems NUC8i7HVK/NUC8i7HVB, BIOS
    HNKBLi70.86A.0067.2021.0528.1339 05/28/2021 [ 534.888716] Call Trace: [ 534.888720] <IRQ> [ 534.888726]
    dump_stack_lvl+0x57/0x7d [ 534.888736] print_address_description.constprop.0+0x1f/0x170 [ 534.888745] ?
    ath11k_dp_rx_update_peer_stats+0x912/0xc10 [ath11k] [ 534.888771] kasan_report.cold+0x83/0xdf [
    534.888783] ? ath11k_dp_rx_update_peer_stats+0x912/0xc10 [ath11k] [ 534.888810]
    ath11k_dp_rx_update_peer_stats+0x912/0xc10 [ath11k] [ 534.888840]
    ath11k_dp_rx_process_mon_status+0x529/0xa70 [ath11k] [ 534.888874] ?
    ath11k_dp_rx_mon_status_bufs_replenish+0x3f0/0x3f0 [ath11k] [ 534.888897] ? check_prev_add+0x20f0/0x20f0 [
    534.888922] ? __lock_acquire+0xb72/0x1870 [ 534.888937] ? find_held_lock+0x33/0x110 [ 534.888954]
    ath11k_dp_rx_process_mon_rings+0x297/0x520 [ath11k] [ 534.888981] ? rcu_read_unlock+0x40/0x40 [
    534.888990] ? ath11k_dp_rx_pdev_alloc+0xd90/0xd90 [ath11k] [ 534.889026]
    ath11k_dp_service_mon_ring+0x67/0xe0 [ath11k] [ 534.889053] ? ath11k_dp_rx_process_mon_rings+0x520/0x520
    [ath11k] [ 534.889075] call_timer_fn+0x167/0x4a0 [ 534.889084] ? add_timer_on+0x3b0/0x3b0 [ 534.889103] ?
    lockdep_hardirqs_on_prepare.part.0+0x18c/0x370 [ 534.889117] __run_timers.part.0+0x539/0x8b0 [ 534.889123]
    ? ath11k_dp_rx_process_mon_rings+0x520/0x520 [ath11k] [ 534.889157] ? call_timer_fn+0x4a0/0x4a0 [
    534.889164] ? mark_lock_irq+0x1c30/0x1c30 [ 534.889173] ? clockevents_program_event+0xdd/0x280 [
    534.889189] ? mark_held_locks+0xa5/0xe0 [ 534.889203] run_timer_softirq+0x97/0x180 [ 534.889213]
    __do_softirq+0x276/0x86a [ 534.889230] __irq_exit_rcu+0x11c/0x180 [ 534.889238] irq_exit_rcu+0x5/0x20 [
    534.889244] sysvec_apic_timer_interrupt+0x8e/0xc0 [ 534.889251] </IRQ> [ 534.889254] <TASK> [ 534.889259]
    asm_sysvec_apic_timer_interrupt+0x12/0x20 [ 534.889265] RIP: 0010:_raw_spin_unlock_irqrestore+0x38/0x70 [
    534.889271] Code: 74 24 10 e8 ea c2 bf fd 48 89 ef e8 12 53 c0 fd 81 e3 00 02 00 00 75 25 9c 58 f6 c4 02
    75 2d 48 85 db 74 01 fb bf 01 00 00 00 <e8> 13 a7 b5 fd 65 8b 05 cc d9 9c 5e 85 c0 74 0a 5b 5d c3 e8 a0 ee
    [ 534.889276] RSP: 0018:ffffc90002e5f880 EFLAGS: 00000206 [ 534.889284] RAX: 0000000000000006 RBX:
    0000000000000200 RCX: ffffffff9f256f10 [ 534.889289] RDX: 0000000000000000 RSI: ffffffffa1c6e420 RDI:
    0000000000000001 [ 534.889293] RBP: ffff8881095e6200 R08: 0000000000000001 R09: ffffffffa40d2b8f [
    534.889298] R10: fffffbfff481a571 R11: 0000000000000001 R12: ffff8881095e6e68 [ 534.889302] R13:
    ffffc90002e5f908 R14: 0000000000000246 R15: 0000000000000000 [ 534.889316] ? mark_lock+0xd0/0x14a0 [
    534.889332] klist_next+0x1d4/0x450 [ 534.889340] ? dpm_wait_for_subordinate+0x2d0/0x2d0 [ 534.889350]
    device_for_each_child+0xa8/0x140 [ 534.889360] ? device_remove_class_symlinks+0x1b0/0x1b0 [ 534.889370] ?
    __lock_release+0x4bd/0x9f0 [ 534.889378] ? dpm_suspend+0x26b/0x3f0 [ 534.889390] dpm_wait_for_subordinate+
    ---truncated--- (CVE-2022-49238)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49238");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
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
