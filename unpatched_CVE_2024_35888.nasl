#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228894);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35888");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35888");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: erspan: make sure erspan_base_hdr is
    present in skb->head syzbot reported a problem in ip6erspan_rcv() [1] Issue is that ip6erspan_rcv() (and
    erspan_rcv()) no longer make sure erspan_base_hdr is present in skb linear part (skb->head) before getting
    @ver field from it. Add the missing pskb_may_pull() calls. v2: Reload iph pointer in erspan_rcv() after
    pskb_may_pull() because skb->head might have changed. [1] BUG: KMSAN: uninit-value in pskb_may_pull_reason
    include/linux/skbuff.h:2742 [inline] BUG: KMSAN: uninit-value in pskb_may_pull include/linux/skbuff.h:2756
    [inline] BUG: KMSAN: uninit-value in ip6erspan_rcv net/ipv6/ip6_gre.c:541 [inline] BUG: KMSAN: uninit-
    value in gre_rcv+0x11f8/0x1930 net/ipv6/ip6_gre.c:610 pskb_may_pull_reason include/linux/skbuff.h:2742
    [inline] pskb_may_pull include/linux/skbuff.h:2756 [inline] ip6erspan_rcv net/ipv6/ip6_gre.c:541 [inline]
    gre_rcv+0x11f8/0x1930 net/ipv6/ip6_gre.c:610 ip6_protocol_deliver_rcu+0x1d4c/0x2ca0
    net/ipv6/ip6_input.c:438 ip6_input_finish net/ipv6/ip6_input.c:483 [inline] NF_HOOK
    include/linux/netfilter.h:314 [inline] ip6_input+0x15d/0x430 net/ipv6/ip6_input.c:492
    ip6_mc_input+0xa7e/0xc80 net/ipv6/ip6_input.c:586 dst_input include/net/dst.h:460 [inline]
    ip6_rcv_finish+0x955/0x970 net/ipv6/ip6_input.c:79 NF_HOOK include/linux/netfilter.h:314 [inline]
    ipv6_rcv+0xde/0x390 net/ipv6/ip6_input.c:310 __netif_receive_skb_one_core net/core/dev.c:5538 [inline]
    __netif_receive_skb+0x1da/0xa00 net/core/dev.c:5652 netif_receive_skb_internal net/core/dev.c:5738
    [inline] netif_receive_skb+0x58/0x660 net/core/dev.c:5798 tun_rx_batched+0x3ee/0x980
    drivers/net/tun.c:1549 tun_get_user+0x5566/0x69e0 drivers/net/tun.c:2002 tun_chr_write_iter+0x3af/0x5d0
    drivers/net/tun.c:2048 call_write_iter include/linux/fs.h:2108 [inline] new_sync_write fs/read_write.c:497
    [inline] vfs_write+0xb63/0x1520 fs/read_write.c:590 ksys_write+0x20f/0x4c0 fs/read_write.c:643
    __do_sys_write fs/read_write.c:655 [inline] __se_sys_write fs/read_write.c:652 [inline]
    __x64_sys_write+0x93/0xe0 fs/read_write.c:652 do_syscall_64+0xd5/0x1f0
    entry_SYSCALL_64_after_hwframe+0x6d/0x75 Uninit was created at: slab_post_alloc_hook mm/slub.c:3804
    [inline] slab_alloc_node mm/slub.c:3845 [inline] kmem_cache_alloc_node+0x613/0xc50 mm/slub.c:3888
    kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:577 __alloc_skb+0x35b/0x7a0 net/core/skbuff.c:668 alloc_skb
    include/linux/skbuff.h:1318 [inline] alloc_skb_with_frags+0xc8/0xbf0 net/core/skbuff.c:6504
    sock_alloc_send_pskb+0xa81/0xbf0 net/core/sock.c:2795 tun_alloc_skb drivers/net/tun.c:1525 [inline]
    tun_get_user+0x209a/0x69e0 drivers/net/tun.c:1846 tun_chr_write_iter+0x3af/0x5d0 drivers/net/tun.c:2048
    call_write_iter include/linux/fs.h:2108 [inline] new_sync_write fs/read_write.c:497 [inline]
    vfs_write+0xb63/0x1520 fs/read_write.c:590 ksys_write+0x20f/0x4c0 fs/read_write.c:643 __do_sys_write
    fs/read_write.c:655 [inline] __se_sys_write fs/read_write.c:652 [inline] __x64_sys_write+0x93/0xe0
    fs/read_write.c:652 do_syscall_64+0xd5/0x1f0 entry_SYSCALL_64_after_hwframe+0x6d/0x75 CPU: 1 PID: 5045
    Comm: syz-executor114 Not tainted 6.9.0-rc1-syzkaller-00021-g962490525cff #0 (CVE-2024-35888)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35888");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
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
