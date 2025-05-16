#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228296);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26857");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26857");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: geneve: make sure to pull inner header
    in geneve_rx() syzbot triggered a bug in geneve_rx() [1] Issue is similar to the one I fixed in commit
    8d975c15c0cd (ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()) We have to save
    skb->network_header in a temporary variable in order to be able to recompute the network_header pointer
    after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure the needed headers are in skb->head.
    [1] BUG: KMSAN: uninit-value in IP_ECN_decapsulate include/net/inet_ecn.h:302 [inline] BUG: KMSAN: uninit-
    value in geneve_rx drivers/net/geneve.c:279 [inline] BUG: KMSAN: uninit-value in
    geneve_udp_encap_recv+0x36f9/0x3c10 drivers/net/geneve.c:391 IP_ECN_decapsulate include/net/inet_ecn.h:302
    [inline] geneve_rx drivers/net/geneve.c:279 [inline] geneve_udp_encap_recv+0x36f9/0x3c10
    drivers/net/geneve.c:391 udp_queue_rcv_one_skb+0x1d39/0x1f20 net/ipv4/udp.c:2108
    udp_queue_rcv_skb+0x6ae/0x6e0 net/ipv4/udp.c:2186 udp_unicast_rcv_skb+0x184/0x4b0 net/ipv4/udp.c:2346
    __udp4_lib_rcv+0x1c6b/0x3010 net/ipv4/udp.c:2422 udp_rcv+0x7d/0xa0 net/ipv4/udp.c:2604
    ip_protocol_deliver_rcu+0x264/0x1300 net/ipv4/ip_input.c:205 ip_local_deliver_finish+0x2b8/0x440
    net/ipv4/ip_input.c:233 NF_HOOK include/linux/netfilter.h:314 [inline] ip_local_deliver+0x21f/0x490
    net/ipv4/ip_input.c:254 dst_input include/net/dst.h:461 [inline] ip_rcv_finish net/ipv4/ip_input.c:449
    [inline] NF_HOOK include/linux/netfilter.h:314 [inline] ip_rcv+0x46f/0x760 net/ipv4/ip_input.c:569
    __netif_receive_skb_one_core net/core/dev.c:5534 [inline] __netif_receive_skb+0x1a6/0x5a0
    net/core/dev.c:5648 process_backlog+0x480/0x8b0 net/core/dev.c:5976 __napi_poll+0xe3/0x980
    net/core/dev.c:6576 napi_poll net/core/dev.c:6645 [inline] net_rx_action+0x8b8/0x1870 net/core/dev.c:6778
    __do_softirq+0x1b7/0x7c5 kernel/softirq.c:553 do_softirq+0x9a/0xf0 kernel/softirq.c:454
    __local_bh_enable_ip+0x9b/0xa0 kernel/softirq.c:381 local_bh_enable include/linux/bottom_half.h:33
    [inline] rcu_read_unlock_bh include/linux/rcupdate.h:820 [inline] __dev_queue_xmit+0x2768/0x51c0
    net/core/dev.c:4378 dev_queue_xmit include/linux/netdevice.h:3171 [inline] packet_xmit+0x9c/0x6b0
    net/packet/af_packet.c:276 packet_snd net/packet/af_packet.c:3081 [inline] packet_sendmsg+0x8aef/0x9f10
    net/packet/af_packet.c:3113 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745
    [inline] __sys_sendto+0x735/0xa10 net/socket.c:2191 __do_sys_sendto net/socket.c:2203 [inline]
    __se_sys_sendto net/socket.c:2199 [inline] __x64_sys_sendto+0x125/0x1c0 net/socket.c:2199 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b Uninit was created at: slab_post_alloc_hook mm/slub.c:3819
    [inline] slab_alloc_node mm/slub.c:3860 [inline] kmem_cache_alloc_node+0x5cb/0xbc0 mm/slub.c:3903
    kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:560 __alloc_skb+0x352/0x790 net/core/skbuff.c:651 alloc_skb
    include/linux/skbuff.h:1296 [inline] alloc_skb_with_frags+0xc8/0xbd0 net/core/skbuff.c:6394
    sock_alloc_send_pskb+0xa80/0xbf0 net/core/sock.c:2783 packet_alloc_skb net/packet/af_packet.c:2930
    [inline] packet_snd net/packet/af_packet.c:3024 [inline] packet_sendmsg+0x70c2/0x9f10
    net/packet/af_packet.c:3113 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745
    [inline] __sys_sendto+0x735/0xa10 net/socket.c:2191 __do_sys_sendto net/socket.c:2203 [inline]
    __se_sys_sendto net/socket.c:2199 [inline] __x64_sys_sendto+0x125/0x1c0 net/socket.c:2199 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b (CVE-2024-26857)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
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
