#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228310);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26725");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26725");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: dpll: fix possible deadlock during
    netlink dump operation Recently, I've been hitting following deadlock warning during dpll pin dump:
    [52804.637962] ====================================================== [52804.638536] WARNING: possible
    circular locking dependency detected [52804.639111] 6.8.0-rc2jiri+ #1 Not tainted [52804.639529]
    ------------------------------------------------------ [52804.640104] python3/2984 is trying to acquire
    lock: [52804.640581] ffff88810e642678 (nlk_cb_mutex-GENERIC){+.+.}-{3:3}, at: netlink_dump+0xb3/0x780
    [52804.641417] but task is already holding lock: [52804.642010] ffffffff83bde4c8 (dpll_lock){+.+.}-{3:3},
    at: dpll_lock_dumpit+0x13/0x20 [52804.642747] which lock already depends on the new lock. [52804.643551]
    the existing dependency chain (in reverse order) is: [52804.644259] -> #1 (dpll_lock){+.+.}-{3:3}:
    [52804.644836] lock_acquire+0x174/0x3e0 [52804.645271] __mutex_lock+0x119/0x1150 [52804.645723]
    dpll_lock_dumpit+0x13/0x20 [52804.646169] genl_start+0x266/0x320 [52804.646578]
    __netlink_dump_start+0x321/0x450 [52804.647056] genl_family_rcv_msg_dumpit+0x155/0x1e0 [52804.647575]
    genl_rcv_msg+0x1ed/0x3b0 [52804.648001] netlink_rcv_skb+0xdc/0x210 [52804.648440] genl_rcv+0x24/0x40
    [52804.648831] netlink_unicast+0x2f1/0x490 [52804.649290] netlink_sendmsg+0x36d/0x660 [52804.649742]
    __sock_sendmsg+0x73/0xc0 [52804.650165] __sys_sendto+0x184/0x210 [52804.650597] __x64_sys_sendto+0x72/0x80
    [52804.651045] do_syscall_64+0x6f/0x140 [52804.651474] entry_SYSCALL_64_after_hwframe+0x46/0x4e
    [52804.652001] -> #0 (nlk_cb_mutex-GENERIC){+.+.}-{3:3}: [52804.652650] check_prev_add+0x1ae/0x1280
    [52804.653107] __lock_acquire+0x1ed3/0x29a0 [52804.653559] lock_acquire+0x174/0x3e0 [52804.653984]
    __mutex_lock+0x119/0x1150 [52804.654423] netlink_dump+0xb3/0x780 [52804.654845]
    __netlink_dump_start+0x389/0x450 [52804.655321] genl_family_rcv_msg_dumpit+0x155/0x1e0 [52804.655842]
    genl_rcv_msg+0x1ed/0x3b0 [52804.656272] netlink_rcv_skb+0xdc/0x210 [52804.656721] genl_rcv+0x24/0x40
    [52804.657119] netlink_unicast+0x2f1/0x490 [52804.657570] netlink_sendmsg+0x36d/0x660 [52804.658022]
    __sock_sendmsg+0x73/0xc0 [52804.658450] __sys_sendto+0x184/0x210 [52804.658877] __x64_sys_sendto+0x72/0x80
    [52804.659322] do_syscall_64+0x6f/0x140 [52804.659752] entry_SYSCALL_64_after_hwframe+0x46/0x4e
    [52804.660281] other info that might help us debug this: [52804.661077] Possible unsafe locking scenario:
    [52804.661671] CPU0 CPU1 [52804.662129] ---- ---- [52804.662577] lock(dpll_lock); [52804.662924]
    lock(nlk_cb_mutex-GENERIC); [52804.663538] lock(dpll_lock); [52804.664073] lock(nlk_cb_mutex-GENERIC);
    [52804.664490] The issue as follows: __netlink_dump_start() calls control->start(cb) with nlk->cb_mutex
    held. In control->start(cb) the dpll_lock is taken. Then nlk->cb_mutex is released and taken again in
    netlink_dump(), while dpll_lock still being held. That leads to ABBA deadlock when another CPU races with
    the same operation. Fix this by moving dpll_lock taking into dumpit() callback which ensures correct lock
    taking order. (CVE-2024-26725)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
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
