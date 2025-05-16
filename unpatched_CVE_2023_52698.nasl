#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226270);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52698");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52698");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: calipso: fix memory leak in
    netlbl_calipso_add_pass() If IPv6 support is disabled at boot (ipv6.disable=1), the calipso_init() ->
    netlbl_calipso_ops_register() function isn't called, and the netlbl_calipso_ops_get() function always
    returns NULL. In this case, the netlbl_calipso_add_pass() function allocates memory for the doi_def
    variable but doesn't free it with the calipso_doi_free(). BUG: memory leak unreferenced object
    0xffff888011d68180 (size 64): comm syz-executor.1, pid 10746, jiffies 4295410986 (age 17.928s) hex dump
    (first 32 bytes): 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 ................ backtrace: [<...>] kmalloc include/linux/slab.h:552 [inline]
    [<...>] netlbl_calipso_add_pass net/netlabel/netlabel_calipso.c:76 [inline] [<...>]
    netlbl_calipso_add+0x22e/0x4f0 net/netlabel/netlabel_calipso.c:111 [<...>]
    genl_family_rcv_msg_doit+0x22f/0x330 net/netlink/genetlink.c:739 [<...>] genl_family_rcv_msg
    net/netlink/genetlink.c:783 [inline] [<...>] genl_rcv_msg+0x341/0x5a0 net/netlink/genetlink.c:800 [<...>]
    netlink_rcv_skb+0x14d/0x440 net/netlink/af_netlink.c:2515 [<...>] genl_rcv+0x29/0x40
    net/netlink/genetlink.c:811 [<...>] netlink_unicast_kernel net/netlink/af_netlink.c:1313 [inline] [<...>]
    netlink_unicast+0x54b/0x800 net/netlink/af_netlink.c:1339 [<...>] netlink_sendmsg+0x90a/0xdf0
    net/netlink/af_netlink.c:1934 [<...>] sock_sendmsg_nosec net/socket.c:651 [inline] [<...>]
    sock_sendmsg+0x157/0x190 net/socket.c:671 [<...>] ____sys_sendmsg+0x712/0x870 net/socket.c:2342 [<...>]
    ___sys_sendmsg+0xf8/0x170 net/socket.c:2396 [<...>] __sys_sendmsg+0xea/0x1b0 net/socket.c:2429 [<...>]
    do_syscall_64+0x30/0x40 arch/x86/entry/common.c:46 [<...>] entry_SYSCALL_64_after_hwframe+0x61/0xc6 Found
    by InfoTeCS on behalf of Linux Verification Center (linuxtesting.org) with Syzkaller [PM: merged via the
    LSM tree at Jakub Kicinski request] (CVE-2023-52698)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52698");

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
