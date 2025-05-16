#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227912);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26882");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26882");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: make sure to pull
    inner header in ip_tunnel_rcv() Apply the same fix than ones found in : 8d975c15c0cd (ip6_tunnel: make
    sure to pull inner header in __ip6_tnl_rcv()) 1ca1ba465e55 (geneve: make sure to pull inner header in
    geneve_rx()) We have to save skb->network_header in a temporary variable in order to be able to recompute
    the network_header pointer after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure the needed
    headers are in skb->head. syzbot reported: BUG: KMSAN: uninit-value in __INET_ECN_decapsulate
    include/net/inet_ecn.h:253 [inline] BUG: KMSAN: uninit-value in INET_ECN_decapsulate
    include/net/inet_ecn.h:275 [inline] BUG: KMSAN: uninit-value in IP_ECN_decapsulate
    include/net/inet_ecn.h:302 [inline] BUG: KMSAN: uninit-value in ip_tunnel_rcv+0xed9/0x2ed0
    net/ipv4/ip_tunnel.c:409 __INET_ECN_decapsulate include/net/inet_ecn.h:253 [inline] INET_ECN_decapsulate
    include/net/inet_ecn.h:275 [inline] IP_ECN_decapsulate include/net/inet_ecn.h:302 [inline]
    ip_tunnel_rcv+0xed9/0x2ed0 net/ipv4/ip_tunnel.c:409 __ipgre_rcv+0x9bc/0xbc0 net/ipv4/ip_gre.c:389
    ipgre_rcv net/ipv4/ip_gre.c:411 [inline] gre_rcv+0x423/0x19f0 net/ipv4/ip_gre.c:447 gre_rcv+0x2a4/0x390
    net/ipv4/gre_demux.c:163 ip_protocol_deliver_rcu+0x264/0x1300 net/ipv4/ip_input.c:205
    ip_local_deliver_finish+0x2b8/0x440 net/ipv4/ip_input.c:233 NF_HOOK include/linux/netfilter.h:314 [inline]
    ip_local_deliver+0x21f/0x490 net/ipv4/ip_input.c:254 dst_input include/net/dst.h:461 [inline]
    ip_rcv_finish net/ipv4/ip_input.c:449 [inline] NF_HOOK include/linux/netfilter.h:314 [inline]
    ip_rcv+0x46f/0x760 net/ipv4/ip_input.c:569 __netif_receive_skb_one_core net/core/dev.c:5534 [inline]
    __netif_receive_skb+0x1a6/0x5a0 net/core/dev.c:5648 netif_receive_skb_internal net/core/dev.c:5734
    [inline] netif_receive_skb+0x58/0x660 net/core/dev.c:5793 tun_rx_batched+0x3ee/0x980
    drivers/net/tun.c:1556 tun_get_user+0x53b9/0x66e0 drivers/net/tun.c:2009 tun_chr_write_iter+0x3af/0x5d0
    drivers/net/tun.c:2055 call_write_iter include/linux/fs.h:2087 [inline] new_sync_write fs/read_write.c:497
    [inline] vfs_write+0xb6b/0x1520 fs/read_write.c:590 ksys_write+0x20f/0x4c0 fs/read_write.c:643
    __do_sys_write fs/read_write.c:655 [inline] __se_sys_write fs/read_write.c:652 [inline]
    __x64_sys_write+0x93/0xd0 fs/read_write.c:652 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b Uninit was
    created at: __alloc_pages+0x9a6/0xe00 mm/page_alloc.c:4590 alloc_pages_mpol+0x62b/0x9d0
    mm/mempolicy.c:2133 alloc_pages+0x1be/0x1e0 mm/mempolicy.c:2204 skb_page_frag_refill+0x2bf/0x7c0
    net/core/sock.c:2909 tun_build_skb drivers/net/tun.c:1686 [inline] tun_get_user+0xe0a/0x66e0
    drivers/net/tun.c:1826 tun_chr_write_iter+0x3af/0x5d0 drivers/net/tun.c:2055 call_write_iter
    include/linux/fs.h:2087 [inline] new_sync_write fs/read_write.c:497 [inline] vfs_write+0xb6b/0x1520
    fs/read_write.c:590 ksys_write+0x20f/0x4c0 fs/read_write.c:643 __do_sys_write fs/read_write.c:655 [inline]
    __se_sys_write fs/read_write.c:652 [inline] __x64_sys_write+0x93/0xd0 fs/read_write.c:652 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b (CVE-2024-26882)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/12");
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
