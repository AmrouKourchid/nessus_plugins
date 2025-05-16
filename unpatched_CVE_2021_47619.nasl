#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224329);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47619");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47619");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: i40e: Fix queues reservation for XDP
    When XDP was configured on a system with large number of CPUs and X722 NIC there was a call trace with
    NULL pointer dereference. i40e 0000:87:00.0: failed to get tracking for 256 queues for VSI 0 err -12 i40e
    0000:87:00.0: setup of MAIN VSI failed BUG: kernel NULL pointer dereference, address: 0000000000000000
    RIP: 0010:i40e_xdp+0xea/0x1b0 [i40e] Call Trace: ? i40e_reconfig_rss_queues+0x130/0x130 [i40e]
    dev_xdp_install+0x61/0xe0 dev_xdp_attach+0x18a/0x4c0 dev_change_xdp_fd+0x1e6/0x220 do_setlink+0x616/0x1030
    ? ahci_port_stop+0x80/0x80 ? ata_qc_issue+0x107/0x1e0 ? lock_timer_base+0x61/0x80 ?
    __mod_timer+0x202/0x380 rtnl_setlink+0xe5/0x170 ? bpf_lsm_binder_transaction+0x10/0x10 ?
    security_capable+0x36/0x50 rtnetlink_rcv_msg+0x121/0x350 ? rtnl_calcit.isra.0+0x100/0x100
    netlink_rcv_skb+0x50/0xf0 netlink_unicast+0x1d3/0x2a0 netlink_sendmsg+0x22a/0x440 sock_sendmsg+0x5e/0x60
    __sys_sendto+0xf0/0x160 ? __sys_getsockname+0x7e/0xc0 ? _copy_from_user+0x3c/0x80 ?
    __sys_setsockopt+0xc8/0x1a0 __x64_sys_sendto+0x20/0x30 do_syscall_64+0x33/0x40
    entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x7f83fa7a39e0 This was caused by PF queue pile
    fragmentation due to flow director VSI queue being placed right after main VSI. Because of this main VSI
    was not able to resize its queue allocation for XDP resulting in no queues allocated for main VSI when XDP
    was turned on. Fix this by always allocating last queue in PF queue pile for a flow director VSI.
    (CVE-2021-47619)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47619");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/04");
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
