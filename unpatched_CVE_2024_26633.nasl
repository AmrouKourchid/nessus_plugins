#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228119);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26633");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26633");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: fix NEXTHDR_FRAGMENT
    handling in ip6_tnl_parse_tlv_enc_lim() syzbot pointed out [1] that NEXTHDR_FRAGMENT handling is broken.
    Reading frag_off can only be done if we pulled enough bytes to skb->head. Currently we might access
    garbage. [1] BUG: KMSAN: uninit-value in ip6_tnl_parse_tlv_enc_lim+0x94f/0xbb0
    ip6_tnl_parse_tlv_enc_lim+0x94f/0xbb0 ipxip6_tnl_xmit net/ipv6/ip6_tunnel.c:1326 [inline]
    ip6_tnl_start_xmit+0xab2/0x1a70 net/ipv6/ip6_tunnel.c:1432 __netdev_start_xmit
    include/linux/netdevice.h:4940 [inline] netdev_start_xmit include/linux/netdevice.h:4954 [inline] xmit_one
    net/core/dev.c:3548 [inline] dev_hard_start_xmit+0x247/0xa10 net/core/dev.c:3564
    __dev_queue_xmit+0x33b8/0x5130 net/core/dev.c:4349 dev_queue_xmit include/linux/netdevice.h:3134 [inline]
    neigh_connected_output+0x569/0x660 net/core/neighbour.c:1592 neigh_output include/net/neighbour.h:542
    [inline] ip6_finish_output2+0x23a9/0x2b30 net/ipv6/ip6_output.c:137 ip6_finish_output+0x855/0x12b0
    net/ipv6/ip6_output.c:222 NF_HOOK_COND include/linux/netfilter.h:303 [inline] ip6_output+0x323/0x610
    net/ipv6/ip6_output.c:243 dst_output include/net/dst.h:451 [inline] ip6_local_out+0xe9/0x140
    net/ipv6/output_core.c:155 ip6_send_skb net/ipv6/ip6_output.c:1952 [inline]
    ip6_push_pending_frames+0x1f9/0x560 net/ipv6/ip6_output.c:1972 rawv6_push_pending_frames+0xbe8/0xdf0
    net/ipv6/raw.c:582 rawv6_sendmsg+0x2b66/0x2e70 net/ipv6/raw.c:920 inet_sendmsg+0x105/0x190
    net/ipv4/af_inet.c:847 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745
    [inline] ____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638
    __sys_sendmsg net/socket.c:2667 [inline] __do_sys_sendmsg net/socket.c:2676 [inline] __se_sys_sendmsg
    net/socket.c:2674 [inline] __x64_sys_sendmsg+0x307/0x490 net/socket.c:2674 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0x44/0x110 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b Uninit was created at: slab_post_alloc_hook+0x129/0xa70
    mm/slab.h:768 slab_alloc_node mm/slub.c:3478 [inline] __kmem_cache_alloc_node+0x5c9/0x970 mm/slub.c:3517
    __do_kmalloc_node mm/slab_common.c:1006 [inline] __kmalloc_node_track_caller+0x118/0x3c0
    mm/slab_common.c:1027 kmalloc_reserve+0x249/0x4a0 net/core/skbuff.c:582 pskb_expand_head+0x226/0x1a00
    net/core/skbuff.c:2098 __pskb_pull_tail+0x13b/0x2310 net/core/skbuff.c:2655 pskb_may_pull_reason
    include/linux/skbuff.h:2673 [inline] pskb_may_pull include/linux/skbuff.h:2681 [inline]
    ip6_tnl_parse_tlv_enc_lim+0x901/0xbb0 net/ipv6/ip6_tunnel.c:408 ipxip6_tnl_xmit net/ipv6/ip6_tunnel.c:1326
    [inline] ip6_tnl_start_xmit+0xab2/0x1a70 net/ipv6/ip6_tunnel.c:1432 __netdev_start_xmit
    include/linux/netdevice.h:4940 [inline] netdev_start_xmit include/linux/netdevice.h:4954 [inline] xmit_one
    net/core/dev.c:3548 [inline] dev_hard_start_xmit+0x247/0xa10 net/core/dev.c:3564
    __dev_queue_xmit+0x33b8/0x5130 net/core/dev.c:4349 dev_queue_xmit include/linux/netdevice.h:3134 [inline]
    neigh_connected_output+0x569/0x660 net/core/neighbour.c:1592 neigh_output include/net/neighbour.h:542
    [inline] ip6_finish_output2+0x23a9/0x2b30 net/ipv6/ip6_output.c:137 ip6_finish_output+0x855/0x12b0
    net/ipv6/ip6_output.c:222 NF_HOOK_COND include/linux/netfilter.h:303 [inline] ip6_output+0x323/0x610
    net/ipv6/ip6_output.c:243 dst_output include/net/dst.h:451 [inline] ip6_local_out+0xe9/0x140
    net/ipv6/output_core.c:155 ip6_send_skb net/ipv6/ip6_output.c:1952 [inline]
    ip6_push_pending_frames+0x1f9/0x560 net/ipv6/ip6_output.c:1972 rawv6_push_pending_frames+0xbe8/0xdf0
    net/ipv6/raw.c:582 rawv6_sendmsg+0x2b66/0x2e70 net/ipv6/raw.c:920 inet_sendmsg+0x105/0x190
    net/ipv4/af_inet.c:847 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745
    [inline] ____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638
    __sys_sendmsg net/socket.c:2667 [inline] __do_sys_sendms ---truncated--- (CVE-2024-26633)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26633");

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
  },
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
