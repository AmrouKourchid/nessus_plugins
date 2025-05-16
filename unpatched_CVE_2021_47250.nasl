#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230145);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47250");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47250");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: ipv4: fix memory leak in
    netlbl_cipsov4_add_std Reported by syzkaller: BUG: memory leak unreferenced object 0xffff888105df7000
    (size 64): comm syz-executor842, pid 360, jiffies 4294824824 (age 22.546s) hex dump (first 32 bytes): 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 ................ backtrace: [<00000000e67ed558>] kmalloc include/linux/slab.h:590 [inline]
    [<00000000e67ed558>] kzalloc include/linux/slab.h:720 [inline] [<00000000e67ed558>] netlbl_cipsov4_add_std
    net/netlabel/netlabel_cipso_v4.c:145 [inline] [<00000000e67ed558>] netlbl_cipsov4_add+0x390/0x2340
    net/netlabel/netlabel_cipso_v4.c:416 [<0000000006040154>] genl_family_rcv_msg_doit.isra.0+0x20e/0x320
    net/netlink/genetlink.c:739 [<00000000204d7a1c>] genl_family_rcv_msg net/netlink/genetlink.c:783 [inline]
    [<00000000204d7a1c>] genl_rcv_msg+0x2bf/0x4f0 net/netlink/genetlink.c:800 [<00000000c0d6a995>]
    netlink_rcv_skb+0x134/0x3d0 net/netlink/af_netlink.c:2504 [<00000000d78b9d2c>] genl_rcv+0x24/0x40
    net/netlink/genetlink.c:811 [<000000009733081b>] netlink_unicast_kernel net/netlink/af_netlink.c:1314
    [inline] [<000000009733081b>] netlink_unicast+0x4a0/0x6a0 net/netlink/af_netlink.c:1340
    [<00000000d5fd43b8>] netlink_sendmsg+0x789/0xc70 net/netlink/af_netlink.c:1929 [<000000000a2d1e40>]
    sock_sendmsg_nosec net/socket.c:654 [inline] [<000000000a2d1e40>] sock_sendmsg+0x139/0x170
    net/socket.c:674 [<00000000321d1969>] ____sys_sendmsg+0x658/0x7d0 net/socket.c:2350 [<00000000964e16bc>]
    ___sys_sendmsg+0xf8/0x170 net/socket.c:2404 [<000000001615e288>] __sys_sendmsg+0xd3/0x190
    net/socket.c:2433 [<000000004ee8b6a5>] do_syscall_64+0x37/0x90 arch/x86/entry/common.c:47
    [<00000000171c7cee>] entry_SYSCALL_64_after_hwframe+0x44/0xae The memory of doi_def->map.std pointing is
    allocated in netlbl_cipsov4_add_std, but no place has freed it. It should be freed in cipso_v4_doi_free
    which frees the cipso DOI resource. (CVE-2021-47250)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47250");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
