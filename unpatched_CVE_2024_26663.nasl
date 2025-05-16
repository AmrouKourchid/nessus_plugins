#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227882);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26663");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26663");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tipc: Check the bearer type before
    calling tipc_udp_nl_bearer_add() syzbot reported the following general protection fault [1]: general
    protection fault, probably for non-canonical address 0xdffffc0000000010: 0000 [#1] PREEMPT SMP KASAN
    KASAN: null-ptr-deref in range [0x0000000000000080-0x0000000000000087] ... RIP:
    0010:tipc_udp_is_known_peer+0x9c/0x250 net/tipc/udp_media.c:291 ... Call Trace: <TASK>
    tipc_udp_nl_bearer_add+0x212/0x2f0 net/tipc/udp_media.c:646 tipc_nl_bearer_add+0x21e/0x360
    net/tipc/bearer.c:1089 genl_family_rcv_msg_doit+0x1fc/0x2e0 net/netlink/genetlink.c:972
    genl_family_rcv_msg net/netlink/genetlink.c:1052 [inline] genl_rcv_msg+0x561/0x800
    net/netlink/genetlink.c:1067 netlink_rcv_skb+0x16b/0x440 net/netlink/af_netlink.c:2544 genl_rcv+0x28/0x40
    net/netlink/genetlink.c:1076 netlink_unicast_kernel net/netlink/af_netlink.c:1341 [inline]
    netlink_unicast+0x53b/0x810 net/netlink/af_netlink.c:1367 netlink_sendmsg+0x8b7/0xd70
    net/netlink/af_netlink.c:1909 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg+0xd5/0x180
    net/socket.c:745 ____sys_sendmsg+0x6ac/0x940 net/socket.c:2584 ___sys_sendmsg+0x135/0x1d0
    net/socket.c:2638 __sys_sendmsg+0x117/0x1e0 net/socket.c:2667 do_syscall_x64 arch/x86/entry/common.c:52
    [inline] do_syscall_64+0x40/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b The
    cause of this issue is that when tipc_nl_bearer_add() is called with the TIPC_NLA_BEARER_UDP_OPTS
    attribute, tipc_udp_nl_bearer_add() is called even if the bearer is not UDP. tipc_udp_is_known_peer()
    called by tipc_udp_nl_bearer_add() assumes that the media_ptr field of the tipc_bearer has an udp_bearer
    type object, so the function goes crazy for non-UDP bearers. This patch fixes the issue by checking the
    bearer type before calling tipc_udp_nl_bearer_add() in tipc_nl_bearer_add(). (CVE-2024-26663)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26663");

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
