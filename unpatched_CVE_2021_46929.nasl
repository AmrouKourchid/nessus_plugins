#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224441);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46929");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46929");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: sctp: use call_rcu to free endpoint
    This patch is to delay the endpoint free by calling call_rcu() to fix another use-after-free issue in
    sctp_sock_dump(): BUG: KASAN: use-after-free in __lock_acquire+0x36d9/0x4c20 Call Trace:
    __lock_acquire+0x36d9/0x4c20 kernel/locking/lockdep.c:3218 lock_acquire+0x1ed/0x520
    kernel/locking/lockdep.c:3844 __raw_spin_lock_bh include/linux/spinlock_api_smp.h:135 [inline]
    _raw_spin_lock_bh+0x31/0x40 kernel/locking/spinlock.c:168 spin_lock_bh include/linux/spinlock.h:334
    [inline] __lock_sock+0x203/0x350 net/core/sock.c:2253 lock_sock_nested+0xfe/0x120 net/core/sock.c:2774
    lock_sock include/net/sock.h:1492 [inline] sctp_sock_dump+0x122/0xb20 net/sctp/diag.c:324
    sctp_for_each_transport+0x2b5/0x370 net/sctp/socket.c:5091 sctp_diag_dump+0x3ac/0x660 net/sctp/diag.c:527
    __inet_diag_dump+0xa8/0x140 net/ipv4/inet_diag.c:1049 inet_diag_dump+0x9b/0x110 net/ipv4/inet_diag.c:1065
    netlink_dump+0x606/0x1080 net/netlink/af_netlink.c:2244 __netlink_dump_start+0x59a/0x7c0
    net/netlink/af_netlink.c:2352 netlink_dump_start include/linux/netlink.h:216 [inline]
    inet_diag_handler_cmd+0x2ce/0x3f0 net/ipv4/inet_diag.c:1170 __sock_diag_cmd net/core/sock_diag.c:232
    [inline] sock_diag_rcv_msg+0x31d/0x410 net/core/sock_diag.c:263 netlink_rcv_skb+0x172/0x440
    net/netlink/af_netlink.c:2477 sock_diag_rcv+0x2a/0x40 net/core/sock_diag.c:274 This issue occurs when asoc
    is peeled off and the old sk is freed after getting it by asoc->base.sk and before calling lock_sock(sk).
    To prevent the sk free, as a holder of the sk, ep should be alive when calling lock_sock(). This patch
    uses call_rcu() and moves sock_put and ep free into sctp_endpoint_destroy_rcu(), so that it's safe to try
    to hold the ep under rcu_read_lock in sctp_transport_traverse_process(). If sctp_endpoint_hold() returns
    true, it means this ep is still alive and we have held it and can continue to dump it; If it returns
    false, it means this ep is dead and can be freed after rcu_read_unlock, and we should skip it. In
    sctp_sock_dump(), after locking the sk, if this ep is different from tsp->asoc->ep, it means during this
    dumping, this asoc was peeled off before calling lock_sock(), and the sk should be skipped; If this ep is
    the same with tsp->asoc->ep, it means no peeloff happens on this asoc, and due to lock_sock, no peeloff
    will happen either until release_sock. Note that delaying endpoint free won't delay the port release, as
    the port release happens in sctp_endpoint_destroy() before calling call_rcu(). Also, freeing endpoint by
    call_rcu() makes it safe to access the sk by asoc->base.sk in sctp_assocs_seq_show() and sctp_rcv().
    Thanks Jones to bring this issue up. v1->v2: - improve the changelog. - add kfree(ep) into
    sctp_endpoint_destroy_rcu(), as Jakub noticed. (CVE-2021-46929)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46929");

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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
