#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229469);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40912");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40912");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: mac80211: Fix deadlock in
    ieee80211_sta_ps_deliver_wakeup() The ieee80211_sta_ps_deliver_wakeup() function takes sta->ps_lock to
    synchronizes with ieee80211_tx_h_unicast_ps_buf() which is called from softirq context. However using only
    spin_lock() to get sta->ps_lock in ieee80211_sta_ps_deliver_wakeup() does not prevent softirq to execute
    on this same CPU, to run ieee80211_tx_h_unicast_ps_buf() and try to take this same lock ending in
    deadlock. Below is an example of rcu stall that arises in such situation. rcu: INFO: rcu_sched self-
    detected stall on CPU rcu: 2-....: (42413413 ticks this GP) idle=b154/1/0x4000000000000000
    softirq=1763/1765 fqs=21206996 rcu: (t=42586894 jiffies g=2057 q=362405 ncpus=4) CPU: 2 PID: 719 Comm:
    wpa_supplicant Tainted: G W 6.4.0-02158-g1b062f552873 #742 Hardware name: RPT (r1) (DT) pstate: 00000005
    (nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : queued_spin_lock_slowpath+0x58/0x2d0 lr :
    invoke_tx_handlers_early+0x5b4/0x5c0 sp : ffff00001ef64660 x29: ffff00001ef64660 x28: ffff000009bc1070
    x27: ffff000009bc0ad8 x26: ffff000009bc0900 x25: ffff00001ef647a8 x24: 0000000000000000 x23:
    ffff000009bc0900 x22: ffff000009bc0900 x21: ffff00000ac0e000 x20: ffff00000a279e00 x19: ffff00001ef646e8
    x18: 0000000000000000 x17: ffff800016468000 x16: ffff00001ef608c0 x15: 0010533c93f64f80 x14:
    0010395c9faa3946 x13: 0000000000000000 x12: 00000000fa83b2da x11: 000000012edeceea x10: ffff0000010fbe00
    x9 : 0000000000895440 x8 : 000000000010533c x7 : ffff00000ad8b740 x6 : ffff00000c350880 x5 :
    0000000000000007 x4 : 0000000000000001 x3 : 0000000000000000 x2 : 0000000000000000 x1 : 0000000000000001
    x0 : ffff00000ac0e0e8 Call trace: queued_spin_lock_slowpath+0x58/0x2d0 ieee80211_tx+0x80/0x12c
    ieee80211_tx_pending+0x110/0x278 tasklet_action_common.constprop.0+0x10c/0x144 tasklet_action+0x20/0x28
    _stext+0x11c/0x284 ____do_softirq+0xc/0x14 call_on_irq_stack+0x24/0x34 do_softirq_own_stack+0x18/0x20
    do_softirq+0x74/0x7c __local_bh_enable_ip+0xa0/0xa4 _ieee80211_wake_txqs+0x3b0/0x4b8
    __ieee80211_wake_queue+0x12c/0x168 ieee80211_add_pending_skbs+0xec/0x138
    ieee80211_sta_ps_deliver_wakeup+0x2a4/0x480 ieee80211_mps_sta_status_update.part.0+0xd8/0x11c
    ieee80211_mps_sta_status_update+0x18/0x24 sta_apply_parameters+0x3bc/0x4c0
    ieee80211_change_station+0x1b8/0x2dc nl80211_set_station+0x444/0x49c
    genl_family_rcv_msg_doit.isra.0+0xa4/0xfc genl_rcv_msg+0x1b0/0x244 netlink_rcv_skb+0x38/0x10c
    genl_rcv+0x34/0x48 netlink_unicast+0x254/0x2bc netlink_sendmsg+0x190/0x3b4 ____sys_sendmsg+0x1e8/0x218
    ___sys_sendmsg+0x68/0x8c __sys_sendmsg+0x44/0x84 __arm64_sys_sendmsg+0x20/0x28 do_el0_svc+0x6c/0xe8
    el0_svc+0x14/0x48 el0t_64_sync_handler+0xb0/0xb4 el0t_64_sync+0x14c/0x150 Using
    spin_lock_bh()/spin_unlock_bh() instead prevents softirq to raise on the same CPU that is holding the
    lock. (CVE-2024-40912)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40912");

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
