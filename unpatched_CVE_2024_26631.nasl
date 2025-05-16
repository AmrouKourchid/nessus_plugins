#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227459);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26631");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26631");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipv6: mcast: fix data-race in
    ipv6_mc_down / mld_ifc_work idev->mc_ifc_count can be written over without proper locking. Originally
    found by syzbot [1], fix this issue by encapsulating calls to mld_ifc_stop_work() (and mld_gq_stop_work()
    for good measure) with mutex_lock() and mutex_unlock() accordingly as these functions should only be
    called with mc_lock per their declarations. [1] BUG: KCSAN: data-race in ipv6_mc_down / mld_ifc_work write
    to 0xffff88813a80c832 of 1 bytes by task 3771 on cpu 0: mld_ifc_stop_work net/ipv6/mcast.c:1080 [inline]
    ipv6_mc_down+0x10a/0x280 net/ipv6/mcast.c:2725 addrconf_ifdown+0xe32/0xf10 net/ipv6/addrconf.c:3949
    addrconf_notify+0x310/0x980 notifier_call_chain kernel/notifier.c:93 [inline]
    raw_notifier_call_chain+0x6b/0x1c0 kernel/notifier.c:461 __dev_notify_flags+0x205/0x3d0
    dev_change_flags+0xab/0xd0 net/core/dev.c:8685 do_setlink+0x9f6/0x2430 net/core/rtnetlink.c:2916
    rtnl_group_changelink net/core/rtnetlink.c:3458 [inline] __rtnl_newlink net/core/rtnetlink.c:3717 [inline]
    rtnl_newlink+0xbb3/0x1670 net/core/rtnetlink.c:3754 rtnetlink_rcv_msg+0x807/0x8c0
    net/core/rtnetlink.c:6558 netlink_rcv_skb+0x126/0x220 net/netlink/af_netlink.c:2545
    rtnetlink_rcv+0x1c/0x20 net/core/rtnetlink.c:6576 netlink_unicast_kernel net/netlink/af_netlink.c:1342
    [inline] netlink_unicast+0x589/0x650 net/netlink/af_netlink.c:1368 netlink_sendmsg+0x66e/0x770
    net/netlink/af_netlink.c:1910 ... write to 0xffff88813a80c832 of 1 bytes by task 22 on cpu 1:
    mld_ifc_work+0x54c/0x7b0 net/ipv6/mcast.c:2653 process_one_work kernel/workqueue.c:2627 [inline]
    process_scheduled_works+0x5b8/0xa30 kernel/workqueue.c:2700 worker_thread+0x525/0x730
    kernel/workqueue.c:2781 ... (CVE-2024-26631)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26631");

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
