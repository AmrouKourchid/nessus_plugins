#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224326);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47242");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47242");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: fix soft lookup in
    subflow_error_report() Maxim reported a soft lookup in subflow_error_report(): watchdog: BUG: soft lockup
    - CPU#0 stuck for 22s! [swapper/0:0] RIP: 0010:native_queued_spin_lock_slowpath RSP: 0018:ffffa859c0003bc0
    EFLAGS: 00000202 RAX: 0000000000000101 RBX: 0000000000000001 RCX: 0000000000000000 RDX: ffff9195c2772d88
    RSI: 0000000000000000 RDI: ffff9195c2772d88 RBP: ffff9195c2772d00 R08: 00000000000067b0 R09:
    c6e31da9eb1e44f4 R10: ffff9195ef379700 R11: ffff9195edb50710 R12: ffff9195c2772d88 R13: ffff9195f500e3d0
    R14: ffff9195ef379700 R15: ffff9195ef379700 FS: 0000000000000000(0000) GS:ffff91961f400000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000000c000407000 CR3:
    0000000002988000 CR4: 00000000000006f0 Call Trace: <IRQ> _raw_spin_lock_bh subflow_error_report
    mptcp_subflow_data_available __mptcp_move_skbs_from_subflow mptcp_data_ready tcp_data_queue
    tcp_rcv_established tcp_v4_do_rcv tcp_v4_rcv ip_protocol_deliver_rcu ip_local_deliver_finish
    __netif_receive_skb_one_core netif_receive_skb rtl8139_poll 8139too __napi_poll net_rx_action __do_softirq
    __irq_exit_rcu common_interrupt </IRQ> The calling function - mptcp_subflow_data_available() - can be
    invoked from different contexts: - plain ssk socket lock - ssk socket lock + mptcp_data_lock - ssk socket
    lock + mptcp_data_lock + msk socket lock. Since subflow_error_report() tries to acquire the
    mptcp_data_lock, the latter two call chains will cause soft lookup. This change addresses the issue moving
    the error reporting call to outer functions, where the held locks list is known and the we can acquire
    only the needed one. (CVE-2021-47242)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47242");

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
