#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228396);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36933");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36933");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: nsh: Restore
    skb->{protocol,data,mac_header} for outer header in nsh_gso_segment(). syzbot triggered various splats
    (see [0] and links) by a crafted GSO packet of VIRTIO_NET_HDR_GSO_UDP layering the following protocols:
    ETH_P_8021AD + ETH_P_NSH + ETH_P_IPV6 + IPPROTO_UDP NSH can encapsulate IPv4, IPv6, Ethernet, NSH, and
    MPLS. As the inner protocol can be Ethernet, NSH GSO handler, nsh_gso_segment(), calls
    skb_mac_gso_segment() to invoke inner protocol GSO handlers. nsh_gso_segment() does the following for the
    original skb before calling skb_mac_gso_segment() 1. reset skb->network_header 2. save the original
    skb->{mac_heaeder,mac_len} in a local variable 3. pull the NSH header 4. resets skb->mac_header 5. set up
    skb->mac_len and skb->protocol for the inner protocol. and does the following for the segmented skb 6. set
    ntohs(ETH_P_NSH) to skb->protocol 7. push the NSH header 8. restore skb->mac_header 9. set skb->mac_header
    + mac_len to skb->network_header 10. restore skb->mac_len There are two problems in 6-7 and 8-9. (a) After
    6 & 7, skb->data points to the NSH header, so the outer header (ETH_P_8021AD in this case) is stripped
    when skb is sent out of netdev. Also, if NSH is encapsulated by NSH + Ethernet (so NSH-Ethernet-NSH),
    skb_pull() in the first nsh_gso_segment() will make skb->data point to the middle of the outer NSH or
    Ethernet header because the Ethernet header is not pulled by the second nsh_gso_segment(). (b) While
    restoring skb->{mac_header,network_header} in 8 & 9, nsh_gso_segment() does not assume that the data in
    the linear buffer is shifted. However, udp6_ufo_fragment() could shift the data and change skb->mac_header
    accordingly as demonstrated by syzbot. If this happens, even the restored skb->mac_header points to the
    middle of the outer header. It seems nsh_gso_segment() has never worked with outer headers so far. At the
    end of nsh_gso_segment(), the outer header must be restored for the segmented skb, instead of the NSH
    header. To do that, let's calculate the outer header position relatively from the inner header and set
    skb->{data,mac_header,protocol} properly. [0]: BUG: KMSAN: uninit-value in ipvlan_process_outbound
    drivers/net/ipvlan/ipvlan_core.c:524 [inline] BUG: KMSAN: uninit-value in ipvlan_xmit_mode_l3
    drivers/net/ipvlan/ipvlan_core.c:602 [inline] BUG: KMSAN: uninit-value in ipvlan_queue_xmit+0xf44/0x16b0
    drivers/net/ipvlan/ipvlan_core.c:668 ipvlan_process_outbound drivers/net/ipvlan/ipvlan_core.c:524 [inline]
    ipvlan_xmit_mode_l3 drivers/net/ipvlan/ipvlan_core.c:602 [inline] ipvlan_queue_xmit+0xf44/0x16b0
    drivers/net/ipvlan/ipvlan_core.c:668 ipvlan_start_xmit+0x5c/0x1a0 drivers/net/ipvlan/ipvlan_main.c:222
    __netdev_start_xmit include/linux/netdevice.h:4989 [inline] netdev_start_xmit
    include/linux/netdevice.h:5003 [inline] xmit_one net/core/dev.c:3547 [inline]
    dev_hard_start_xmit+0x244/0xa10 net/core/dev.c:3563 __dev_queue_xmit+0x33ed/0x51c0 net/core/dev.c:4351
    dev_queue_xmit include/linux/netdevice.h:3171 [inline] packet_xmit+0x9c/0x6b0 net/packet/af_packet.c:276
    packet_snd net/packet/af_packet.c:3081 [inline] packet_sendmsg+0x8aef/0x9f10 net/packet/af_packet.c:3113
    sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745 [inline]
    __sys_sendto+0x735/0xa10 net/socket.c:2191 __do_sys_sendto net/socket.c:2203 [inline] __se_sys_sendto
    net/socket.c:2199 [inline] __x64_sys_sendto+0x125/0x1c0 net/socket.c:2199 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b Uninit was created at: slab_post_alloc_hook mm/slub.c:3819
    [inline] slab_alloc_node mm/slub.c:3860 [inline] __do_kmalloc_node mm/slub.c:3980 [inline]
    __kmalloc_node_track_caller+0x705/0x1000 mm/slub.c:4001 kmalloc_reserve+0x249/0x4a0 net/core/skbuff.c:582
    __ ---truncated--- (CVE-2024-36933)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/23");
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
