#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226086);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52778");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52778");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: deal with large GSO size After
    the blamed commit below, the TCP sockets (and the MPTCP subflows) can build egress packets larger than
    64K. That exceeds the maximum DSS data size, the length being misrepresent on the wire and the stream
    being corrupted, as later observed on the receiver: WARNING: CPU: 0 PID: 9696 at net/mptcp/protocol.c:705
    __mptcp_move_skbs_from_subflow+0x2604/0x26e0 CPU: 0 PID: 9696 Comm: syz-executor.7 Not tainted
    6.6.0-rc5-gcd8bdf563d46 #45 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7
    04/01/2014 netlink: 8 bytes leftover after parsing attributes in process `syz-executor.4'. RIP:
    0010:__mptcp_move_skbs_from_subflow+0x2604/0x26e0 net/mptcp/protocol.c:705 RSP: 0018:ffffc90000006e80
    EFLAGS: 00010246 RAX: ffffffff83e9f674 RBX: ffff88802f45d870 RCX: ffff888102ad0000 netlink: 8 bytes
    leftover after parsing attributes in process `syz-executor.4'. RDX: 0000000080000303 RSI: 0000000000013908
    RDI: 0000000000003908 RBP: ffffc90000007110 R08: ffffffff83e9e078 R09: 1ffff1100e548c8a R10:
    dffffc0000000000 R11: ffffed100e548c8b R12: 0000000000013908 R13: dffffc0000000000 R14: 0000000000003908
    R15: 000000000031cf29 FS: 00007f239c47e700(0000) GS:ffff88811b200000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f239c45cd78 CR3: 000000006a66c006 CR4: 0000000000770ef0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000600 PKRU: 55555554 Call Trace: <IRQ> mptcp_data_ready+0x263/0xac0
    net/mptcp/protocol.c:819 subflow_data_ready+0x268/0x6d0 net/mptcp/subflow.c:1409
    tcp_data_queue+0x21a1/0x7a60 net/ipv4/tcp_input.c:5151 tcp_rcv_established+0x950/0x1d90
    net/ipv4/tcp_input.c:6098 tcp_v6_do_rcv+0x554/0x12f0 net/ipv6/tcp_ipv6.c:1483 tcp_v6_rcv+0x2e26/0x3810
    net/ipv6/tcp_ipv6.c:1749 ip6_protocol_deliver_rcu+0xd6b/0x1ae0 net/ipv6/ip6_input.c:438
    ip6_input+0x1c5/0x470 net/ipv6/ip6_input.c:483 ipv6_rcv+0xef/0x2c0 include/linux/netfilter.h:304
    __netif_receive_skb+0x1ea/0x6a0 net/core/dev.c:5532 process_backlog+0x353/0x660 net/core/dev.c:5974
    __napi_poll+0xc6/0x5a0 net/core/dev.c:6536 net_rx_action+0x6a0/0xfd0 net/core/dev.c:6603
    __do_softirq+0x184/0x524 kernel/softirq.c:553 do_softirq+0xdd/0x130 kernel/softirq.c:454 Address the issue
    explicitly bounding the maximum GSO size to what MPTCP actually allows. (CVE-2023-52778)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/13");
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
