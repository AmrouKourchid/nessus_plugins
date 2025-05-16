#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227588);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26615");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26615");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/smc: fix illegal rmb_desc access
    in SMC-D connection dump A crash was found when dumping SMC-D connections. It can be reproduced by
    following steps: - run nginx/wrk test: smc_run nginx smc_run wrk -t 16 -c 1000 -d <duration> -H
    'Connection: Close' <URL> - continuously dump SMC-D connections in parallel: watch -n 1 'smcss -D' BUG:
    kernel NULL pointer dereference, address: 0000000000000030 CPU: 2 PID: 7204 Comm: smcss Kdump: loaded
    Tainted: G E 6.7.0+ #55 RIP: 0010:__smc_diag_dump.constprop.0+0x5e5/0x620 [smc_diag] Call Trace: <TASK> ?
    __die+0x24/0x70 ? page_fault_oops+0x66/0x150 ? exc_page_fault+0x69/0x140 ? asm_exc_page_fault+0x26/0x30 ?
    __smc_diag_dump.constprop.0+0x5e5/0x620 [smc_diag] ? __kmalloc_node_track_caller+0x35d/0x430 ?
    __alloc_skb+0x77/0x170 smc_diag_dump_proto+0xd0/0xf0 [smc_diag] smc_diag_dump+0x26/0x60 [smc_diag]
    netlink_dump+0x19f/0x320 __netlink_dump_start+0x1dc/0x300 smc_diag_handler_dump+0x6a/0x80 [smc_diag] ?
    __pfx_smc_diag_dump+0x10/0x10 [smc_diag] sock_diag_rcv_msg+0x121/0x140 ? __pfx_sock_diag_rcv_msg+0x10/0x10
    netlink_rcv_skb+0x5a/0x110 sock_diag_rcv+0x28/0x40 netlink_unicast+0x22a/0x330 netlink_sendmsg+0x1f8/0x420
    __sock_sendmsg+0xb0/0xc0 ____sys_sendmsg+0x24e/0x300 ? copy_msghdr_from_user+0x62/0x80
    ___sys_sendmsg+0x7c/0xd0 ? __do_fault+0x34/0x160 ? do_read_fault+0x5f/0x100 ? do_fault+0xb0/0x110 ?
    __handle_mm_fault+0x2b0/0x6c0 __sys_sendmsg+0x4d/0x80 do_syscall_64+0x69/0x180
    entry_SYSCALL_64_after_hwframe+0x6e/0x76 It is possible that the connection is in process of being
    established when we dump it. Assumed that the connection has been registered in a link group by
    smc_conn_create() but the rmb_desc has not yet been initialized by smc_buf_create(), thus causing the
    illegal access to conn->rmb_desc. So fix it by checking before dump. (CVE-2024-26615)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26615");

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
