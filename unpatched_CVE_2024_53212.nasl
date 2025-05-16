#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231967);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53212");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53212");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netlink: fix false positive warning in
    extack during dumps Commit under fixes extended extack reporting to dumps. It works under normal
    conditions, because extack errors are usually reported during ->start() or the first ->dump(), it's quite
    rare that the dump starts okay but fails later. If the dump does fail later, however, the input skb will
    already have the initiating message pulled, so checking if bad attr falls within skb->data will fail.
    Switch the check to using nlh, which is always valid. syzbot found a way to hit that scenario by filling
    up the receive queue. In this case we initiate a dump but don't call ->dump() until there is read space
    for an skb. WARNING: CPU: 1 PID: 5845 at net/netlink/af_netlink.c:2210 netlink_ack_tlv_fill+0x1a8/0x560
    net/netlink/af_netlink.c:2209 RIP: 0010:netlink_ack_tlv_fill+0x1a8/0x560 net/netlink/af_netlink.c:2209
    Call Trace: <TASK> netlink_dump_done+0x513/0x970 net/netlink/af_netlink.c:2250 netlink_dump+0x91f/0xe10
    net/netlink/af_netlink.c:2351 netlink_recvmsg+0x6bb/0x11d0 net/netlink/af_netlink.c:1983
    sock_recvmsg_nosec net/socket.c:1051 [inline] sock_recvmsg+0x22f/0x280 net/socket.c:1073
    __sys_recvfrom+0x246/0x3d0 net/socket.c:2267 __do_sys_recvfrom net/socket.c:2285 [inline]
    __se_sys_recvfrom net/socket.c:2281 [inline] __x64_sys_recvfrom+0xde/0x100 net/socket.c:2281
    do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7ff37dd17a79 (CVE-2024-53212)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
