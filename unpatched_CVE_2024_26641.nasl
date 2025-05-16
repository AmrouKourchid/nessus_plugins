#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228314);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26641");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26641");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: make sure to pull inner
    header in __ip6_tnl_rcv() syzbot found __ip6_tnl_rcv() could access unitiliazed data [1]. Call
    pskb_inet_may_pull() to fix this, and initialize ipv6h variable after this call as it can change
    skb->head. [1] BUG: KMSAN: uninit-value in __INET_ECN_decapsulate include/net/inet_ecn.h:253 [inline] BUG:
    KMSAN: uninit-value in INET_ECN_decapsulate include/net/inet_ecn.h:275 [inline] BUG: KMSAN: uninit-value
    in IP6_ECN_decapsulate+0x7df/0x1e50 include/net/inet_ecn.h:321 __INET_ECN_decapsulate
    include/net/inet_ecn.h:253 [inline] INET_ECN_decapsulate include/net/inet_ecn.h:275 [inline]
    IP6_ECN_decapsulate+0x7df/0x1e50 include/net/inet_ecn.h:321 ip6ip6_dscp_ecn_decapsulate+0x178/0x1b0
    net/ipv6/ip6_tunnel.c:727 __ip6_tnl_rcv+0xd4e/0x1590 net/ipv6/ip6_tunnel.c:845 ip6_tnl_rcv+0xce/0x100
    net/ipv6/ip6_tunnel.c:888 gre_rcv+0x143f/0x1870 ip6_protocol_deliver_rcu+0xda6/0x2a60
    net/ipv6/ip6_input.c:438 ip6_input_finish net/ipv6/ip6_input.c:483 [inline] NF_HOOK
    include/linux/netfilter.h:314 [inline] ip6_input+0x15d/0x430 net/ipv6/ip6_input.c:492
    ip6_mc_input+0xa7e/0xc80 net/ipv6/ip6_input.c:586 dst_input include/net/dst.h:461 [inline]
    ip6_rcv_finish+0x5db/0x870 net/ipv6/ip6_input.c:79 NF_HOOK include/linux/netfilter.h:314 [inline]
    ipv6_rcv+0xda/0x390 net/ipv6/ip6_input.c:310 __netif_receive_skb_one_core net/core/dev.c:5532 [inline]
    __netif_receive_skb+0x1a6/0x5a0 net/core/dev.c:5646 netif_receive_skb_internal net/core/dev.c:5732
    [inline] netif_receive_skb+0x58/0x660 net/core/dev.c:5791 tun_rx_batched+0x3ee/0x980
    drivers/net/tun.c:1555 tun_get_user+0x53af/0x66d0 drivers/net/tun.c:2002 tun_chr_write_iter+0x3af/0x5d0
    drivers/net/tun.c:2048 call_write_iter include/linux/fs.h:2084 [inline] new_sync_write fs/read_write.c:497
    [inline] vfs_write+0x786/0x1200 fs/read_write.c:590 ksys_write+0x20f/0x4c0 fs/read_write.c:643
    __do_sys_write fs/read_write.c:655 [inline] __se_sys_write fs/read_write.c:652 [inline]
    __x64_sys_write+0x93/0xd0 fs/read_write.c:652 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0x6d/0x140 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b Uninit was
    created at: slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768 slab_alloc_node mm/slub.c:3478 [inline]
    kmem_cache_alloc_node+0x5e9/0xb10 mm/slub.c:3523 kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:560
    __alloc_skb+0x318/0x740 net/core/skbuff.c:651 alloc_skb include/linux/skbuff.h:1286 [inline]
    alloc_skb_with_frags+0xc8/0xbd0 net/core/skbuff.c:6334 sock_alloc_send_pskb+0xa80/0xbf0
    net/core/sock.c:2787 tun_alloc_skb drivers/net/tun.c:1531 [inline] tun_get_user+0x1e8a/0x66d0
    drivers/net/tun.c:1846 tun_chr_write_iter+0x3af/0x5d0 drivers/net/tun.c:2048 call_write_iter
    include/linux/fs.h:2084 [inline] new_sync_write fs/read_write.c:497 [inline] vfs_write+0x786/0x1200
    fs/read_write.c:590 ksys_write+0x20f/0x4c0 fs/read_write.c:643 __do_sys_write fs/read_write.c:655 [inline]
    __se_sys_write fs/read_write.c:652 [inline] __x64_sys_write+0x93/0xd0 fs/read_write.c:652 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0x6d/0x140 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b CPU: 0 PID: 5034 Comm: syz-executor331 Not tainted
    6.7.0-syzkaller-00562-g9f8413c4a66f #0 Hardware name: Google Google Compute Engine/Google Compute Engine,
    BIOS Google 11/17/2023 (CVE-2024-26641)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26641");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
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
