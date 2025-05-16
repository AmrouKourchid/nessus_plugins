#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224430);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47038");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47038");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Bluetooth: avoid deadlock between
    hci_dev->lock and socket lock Commit eab2404ba798 (Bluetooth: Add BT_PHY socket option) added a
    dependency between socket lock and hci_dev->lock that could lead to deadlock. It turns out that
    hci_conn_get_phy() is not in any way relying on hdev being immutable during the runtime of this function,
    neither does it even look at any of the members of hdev, and as such there is no need to hold that lock.
    This fixes the lockdep splat below: ====================================================== WARNING:
    possible circular locking dependency detected 5.12.0-rc1-00026-g73d464503354 #10 Not tainted
    ------------------------------------------------------ bluetoothd/1118 is trying to acquire lock:
    ffff8f078383c078 (&hdev->lock){+.+.}-{3:3}, at: hci_conn_get_phy+0x1c/0x150 [bluetooth] but task is
    already holding lock: ffff8f07e831d920 (sk_lock-AF_BLUETOOTH-BTPROTO_L2CAP){+.+.}-{0:0}, at:
    l2cap_sock_getsockopt+0x8b/0x610 which lock already depends on the new lock. the existing dependency chain
    (in reverse order) is: -> #3 (sk_lock-AF_BLUETOOTH-BTPROTO_L2CAP){+.+.}-{0:0}: lock_sock_nested+0x72/0xa0
    l2cap_sock_ready_cb+0x18/0x70 [bluetooth] l2cap_config_rsp+0x27a/0x520 [bluetooth]
    l2cap_sig_channel+0x658/0x1330 [bluetooth] l2cap_recv_frame+0x1ba/0x310 [bluetooth]
    hci_rx_work+0x1cc/0x640 [bluetooth] process_one_work+0x244/0x5f0 worker_thread+0x3c/0x380
    kthread+0x13e/0x160 ret_from_fork+0x22/0x30 -> #2 (&chan->lock#2/1){+.+.}-{3:3}: __mutex_lock+0xa3/0xa10
    l2cap_chan_connect+0x33a/0x940 [bluetooth] l2cap_sock_connect+0x141/0x2a0 [bluetooth]
    __sys_connect+0x9b/0xc0 __x64_sys_connect+0x16/0x20 do_syscall_64+0x33/0x80
    entry_SYSCALL_64_after_hwframe+0x44/0xae -> #1 (&conn->chan_lock){+.+.}-{3:3}: __mutex_lock+0xa3/0xa10
    l2cap_chan_connect+0x322/0x940 [bluetooth] l2cap_sock_connect+0x141/0x2a0 [bluetooth]
    __sys_connect+0x9b/0xc0 __x64_sys_connect+0x16/0x20 do_syscall_64+0x33/0x80
    entry_SYSCALL_64_after_hwframe+0x44/0xae -> #0 (&hdev->lock){+.+.}-{3:3}: __lock_acquire+0x147a/0x1a50
    lock_acquire+0x277/0x3d0 __mutex_lock+0xa3/0xa10 hci_conn_get_phy+0x1c/0x150 [bluetooth]
    l2cap_sock_getsockopt+0x5a9/0x610 [bluetooth] __sys_getsockopt+0xcc/0x200 __x64_sys_getsockopt+0x20/0x30
    do_syscall_64+0x33/0x80 entry_SYSCALL_64_after_hwframe+0x44/0xae other info that might help us debug this:
    Chain exists of: &hdev->lock --> &chan->lock#2/1 --> sk_lock-AF_BLUETOOTH-BTPROTO_L2CAP Possible unsafe
    locking scenario: CPU0 CPU1 ---- ---- lock(sk_lock-AF_BLUETOOTH-BTPROTO_L2CAP); lock(&chan->lock#2/1);
    lock(sk_lock-AF_BLUETOOTH-BTPROTO_L2CAP); lock(&hdev->lock); *** DEADLOCK *** 1 lock held by
    bluetoothd/1118: #0: ffff8f07e831d920 (sk_lock-AF_BLUETOOTH-BTPROTO_L2CAP){+.+.}-{0:0}, at:
    l2cap_sock_getsockopt+0x8b/0x610 [bluetooth] stack backtrace: CPU: 3 PID: 1118 Comm: bluetoothd Not
    tainted 5.12.0-rc1-00026-g73d464503354 #10 Hardware name: LENOVO 20K5S22R00/20K5S22R00, BIOS R0IET38W
    (1.16 ) 05/31/2017 Call Trace: dump_stack+0x7f/0xa1 check_noncircular+0x105/0x120 ?
    __lock_acquire+0x147a/0x1a50 __lock_acquire+0x147a/0x1a50 lock_acquire+0x277/0x3d0 ?
    hci_conn_get_phy+0x1c/0x150 [bluetooth] ? __lock_acquire+0x2e1/0x1a50 ? lock_is_held_type+0xb4/0x120 ?
    hci_conn_get_phy+0x1c/0x150 [bluetooth] __mutex_lock+0xa3/0xa10 ? hci_conn_get_phy+0x1c/0x150 [bluetooth]
    ? lock_acquire+0x277/0x3d0 ? mark_held_locks+0x49/0x70 ? mark_held_locks+0x49/0x70 ?
    hci_conn_get_phy+0x1c/0x150 [bluetooth] hci_conn_get_phy+0x ---truncated--- (CVE-2021-47038)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47038");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
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
