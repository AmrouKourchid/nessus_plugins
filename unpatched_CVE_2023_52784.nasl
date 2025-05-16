#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226879);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52784");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52784");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bonding: stop the device in
    bond_setup_by_slave() Commit 9eed321cde22 (net: lapbether: only support ethernet devices) has been able
    to keep syzbot away from net/lapb, until today. In the following splat [1], the issue is that a lapbether
    device has been created on a bonding device without members. Then adding a non ARPHRD_ETHER member forced
    the bonding master to change its type. The fix is to make sure we call dev_close() in
    bond_setup_by_slave() so that the potential linked lapbether devices (or any other devices having
    assumptions on the physical device) are removed. A similar bug has been addressed in commit 40baec225765
    (bonding: fix panic on non-ARPHRD_ETHER enslave failure) [1] skbuff: skb_under_panic:
    text:ffff800089508810 len:44 put:40 head:ffff0000c78e7c00 data:ffff0000c78e7bea tail:0x16 end:0x140
    dev:bond0 kernel BUG at net/core/skbuff.c:192 ! Internal error: Oops - BUG: 00000000f2000800 [#1] PREEMPT
    SMP Modules linked in: CPU: 0 PID: 6007 Comm: syz-executor383 Not tainted 6.6.0-rc3-syzkaller-
    gbf6547d8715b #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 08/04/2023
    pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : skb_panic net/core/skbuff.c:188
    [inline] pc : skb_under_panic+0x13c/0x140 net/core/skbuff.c:202 lr : skb_panic net/core/skbuff.c:188
    [inline] lr : skb_under_panic+0x13c/0x140 net/core/skbuff.c:202 sp : ffff800096a06aa0 x29:
    ffff800096a06ab0 x28: ffff800096a06ba0 x27: dfff800000000000 x26: ffff0000ce9b9b50 x25: 0000000000000016
    x24: ffff0000c78e7bea x23: ffff0000c78e7c00 x22: 000000000000002c x21: 0000000000000140 x20:
    0000000000000028 x19: ffff800089508810 x18: ffff800096a06100 x17: 0000000000000000 x16: ffff80008a629a3c
    x15: 0000000000000001 x14: 1fffe00036837a32 x13: 0000000000000000 x12: 0000000000000000 x11:
    0000000000000201 x10: 0000000000000000 x9 : cb50b496c519aa00 x8 : cb50b496c519aa00 x7 : 0000000000000001
    x6 : 0000000000000001 x5 : ffff800096a063b8 x4 : ffff80008e280f80 x3 : ffff8000805ad11c x2 :
    0000000000000001 x1 : 0000000100000201 x0 : 0000000000000086 Call trace: skb_panic net/core/skbuff.c:188
    [inline] skb_under_panic+0x13c/0x140 net/core/skbuff.c:202 skb_push+0xf0/0x108 net/core/skbuff.c:2446
    ip6gre_header+0xbc/0x738 net/ipv6/ip6_gre.c:1384 dev_hard_header include/linux/netdevice.h:3136 [inline]
    lapbeth_data_transmit+0x1c4/0x298 drivers/net/wan/lapbether.c:257 lapb_data_transmit+0x8c/0xb0
    net/lapb/lapb_iface.c:447 lapb_transmit_buffer+0x178/0x204 net/lapb/lapb_out.c:149
    lapb_send_control+0x220/0x320 net/lapb/lapb_subr.c:251 __lapb_disconnect_request+0x9c/0x17c
    net/lapb/lapb_iface.c:326 lapb_device_event+0x288/0x4e0 net/lapb/lapb_iface.c:492
    notifier_call_chain+0x1a4/0x510 kernel/notifier.c:93 raw_notifier_call_chain+0x3c/0x50
    kernel/notifier.c:461 call_netdevice_notifiers_info net/core/dev.c:1970 [inline]
    call_netdevice_notifiers_extack net/core/dev.c:2008 [inline] call_netdevice_notifiers net/core/dev.c:2022
    [inline] __dev_close_many+0x1b8/0x3c4 net/core/dev.c:1508 dev_close_many+0x1e0/0x470 net/core/dev.c:1559
    dev_close+0x174/0x250 net/core/dev.c:1585 lapbeth_device_event+0x2e4/0x958 drivers/net/wan/lapbether.c:466
    notifier_call_chain+0x1a4/0x510 kernel/notifier.c:93 raw_notifier_call_chain+0x3c/0x50
    kernel/notifier.c:461 call_netdevice_notifiers_info net/core/dev.c:1970 [inline]
    call_netdevice_notifiers_extack net/core/dev.c:2008 [inline] call_netdevice_notifiers net/core/dev.c:2022
    [inline] __dev_close_many+0x1b8/0x3c4 net/core/dev.c:1508 dev_close_many+0x1e0/0x470 net/core/dev.c:1559
    dev_close+0x174/0x250 net/core/dev.c:1585 bond_enslave+0x2298/0x30cc drivers/net/bonding/bond_main.c:2332
    bond_do_ioctl+0x268/0xc64 drivers/net/bonding/bond_main.c:4539 dev_ifsioc+0x754/0x9ac
    dev_ioctl+0x4d8/0xd34 net/core/dev_ioctl.c:786 sock_do_ioctl+0x1d4/0x2d0 net/socket.c:1217
    sock_ioctl+0x4e8/0x834 net/socket.c:1322 vfs_ioctl fs/ioctl.c:51 [inline] __do_ ---truncated---
    (CVE-2023-52784)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52784");

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
