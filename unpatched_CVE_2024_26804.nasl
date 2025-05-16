#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227502);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26804");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26804");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: prevent perpetual
    headroom growth syzkaller triggered following kasan splat: BUG: KASAN: use-after-free in
    __skb_flow_dissect+0x19d1/0x7a50 net/core/flow_dissector.c:1170 Read of size 1 at addr ffff88812fb4000e by
    task syz-executor183/5191 [..] kasan_report+0xda/0x110 mm/kasan/report.c:588
    __skb_flow_dissect+0x19d1/0x7a50 net/core/flow_dissector.c:1170 skb_flow_dissect_flow_keys
    include/linux/skbuff.h:1514 [inline] ___skb_get_hash net/core/flow_dissector.c:1791 [inline]
    __skb_get_hash+0xc7/0x540 net/core/flow_dissector.c:1856 skb_get_hash include/linux/skbuff.h:1556 [inline]
    ip_tunnel_xmit+0x1855/0x33c0 net/ipv4/ip_tunnel.c:748 ipip_tunnel_xmit+0x3cc/0x4e0 net/ipv4/ipip.c:308
    __netdev_start_xmit include/linux/netdevice.h:4940 [inline] netdev_start_xmit
    include/linux/netdevice.h:4954 [inline] xmit_one net/core/dev.c:3548 [inline]
    dev_hard_start_xmit+0x13d/0x6d0 net/core/dev.c:3564 __dev_queue_xmit+0x7c1/0x3d60 net/core/dev.c:4349
    dev_queue_xmit include/linux/netdevice.h:3134 [inline] neigh_connected_output+0x42c/0x5d0
    net/core/neighbour.c:1592 ... ip_finish_output2+0x833/0x2550 net/ipv4/ip_output.c:235
    ip_finish_output+0x31/0x310 net/ipv4/ip_output.c:323 .. iptunnel_xmit+0x5b4/0x9b0
    net/ipv4/ip_tunnel_core.c:82 ip_tunnel_xmit+0x1dbc/0x33c0 net/ipv4/ip_tunnel.c:831 ipgre_xmit+0x4a1/0x980
    net/ipv4/ip_gre.c:665 __netdev_start_xmit include/linux/netdevice.h:4940 [inline] netdev_start_xmit
    include/linux/netdevice.h:4954 [inline] xmit_one net/core/dev.c:3548 [inline]
    dev_hard_start_xmit+0x13d/0x6d0 net/core/dev.c:3564 ... The splat occurs because skb->data points past
    skb->head allocated area. This is because neigh layer does: __skb_pull(skb, skb_network_offset(skb)); ...
    but skb_network_offset() returns a negative offset and __skb_pull() arg is unsigned. IOW, we skb->data
    gets adjusted by a huge value. The negative value is returned because skb->head and skb->data distance
    is more than 64k and skb->network_header (u16) has wrapped around. The bug is in the ip_tunnel
    infrastructure, which can cause dev->needed_headroom to increment ad infinitum. The syzkaller reproducer
    consists of packets getting routed via a gre tunnel, and route of gre encapsulated packets pointing at
    another (ipip) tunnel. The ipip encapsulation finds gre0 as next output device. This results in the
    following pattern: 1). First packet is to be sent out via gre0. Route lookup found an output device,
    ipip0. 2). ip_tunnel_xmit for gre0 bumps gre0->needed_headroom based on the future output device,
    rt.dev->needed_headroom (ipip0). 3). ip output / start_xmit moves skb on to ipip0. which runs the same
    code path again (xmit recursion). 4). Routing step for the post-gre0-encap packet finds gre0 as output
    device to use for ipip0 encapsulated packet. tunl0->needed_headroom is then incremented based on the
    (already bumped) gre0 device headroom. This repeats for every future packet: gre0->needed_headroom gets
    inflated because previous packets' ipip0 step incremented rt->dev (gre0) headroom, and ipip0 incremented
    because gre0 needed_headroom was increased. For each subsequent packet, gre/ipip0->needed_headroom grows
    until post-expand-head reallocations result in a skb->head/data distance of more than 64k. Once that
    happens, skb->network_header (u16) wraps around when pskb_expand_head tries to make sure that
    skb_network_offset() is unchanged after the headroom expansion/reallocation. After this
    skb_network_offset(skb) returns a different (and negative) result post headroom expansion. The next trip
    to neigh layer (or anything else that would __skb_pull the network header) makes skb->data point to a
    memory location outside skb->head area. v2: Cap the needed_headroom update to an arbitarily chosen
    upperlimit to prevent perpetual increase instead of dropping the headroom increment completely.
    (CVE-2024-26804)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26804");

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
