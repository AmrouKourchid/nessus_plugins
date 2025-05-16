#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225647);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48729");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48729");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: IB/hfi1: Fix panic with larger ipoib
    send_queue_size When the ipoib send_queue_size is increased from the default the following panic happens:
    RIP: 0010:hfi1_ipoib_drain_tx_ring+0x45/0xf0 [hfi1] Code: 31 e4 eb 0f 8b 85 c8 02 00 00 41 83 c4 01 44 39
    e0 76 60 8b 8d cc 02 00 00 44 89 e3 be 01 00 00 00 d3 e3 48 03 9d c0 02 00 00 <c7> 83 18 01 00 00 00 00 00
    00 48 8b bb 30 01 00 00 e8 25 af a7 e0 RSP: 0018:ffffc9000798f4a0 EFLAGS: 00010286 RAX: 0000000000008000
    RBX: ffffc9000aa0f000 RCX: 000000000000000f RDX: 0000000000000000 RSI: 0000000000000001 RDI:
    0000000000000000 RBP: ffff88810ff08000 R08: ffff88889476d900 R09: 0000000000000101 R10: 0000000000000000
    R11: ffffc90006590ff8 R12: 0000000000000200 R13: ffffc9000798fba8 R14: 0000000000000000 R15:
    0000000000000001 FS: 00007fd0f79cc3c0(0000) GS:ffff88885fb00000(0000) knlGS:0000000000000000 CS: 0010 DS:
    0000 ES: 0000 CR0: 0000000080050033 CR2: ffffc9000aa0f118 CR3: 0000000889c84001 CR4: 00000000001706e0 Call
    Trace: <TASK> hfi1_ipoib_napi_tx_disable+0x45/0x60 [hfi1] hfi1_ipoib_dev_stop+0x18/0x80 [hfi1]
    ipoib_ib_dev_stop+0x1d/0x40 [ib_ipoib] ipoib_stop+0x48/0xc0 [ib_ipoib] __dev_close_many+0x9e/0x110
    __dev_change_flags+0xd9/0x210 dev_change_flags+0x21/0x60 do_setlink+0x31c/0x10f0 ?
    __nla_validate_parse+0x12d/0x1a0 ? __nla_parse+0x21/0x30 ? inet6_validate_link_af+0x5e/0xf0 ?
    cpumask_next+0x1f/0x20 ? __snmp6_fill_stats64.isra.53+0xbb/0x140 ? __nla_validate_parse+0x47/0x1a0
    __rtnl_newlink+0x530/0x910 ? pskb_expand_head+0x73/0x300 ? __kmalloc_node_track_caller+0x109/0x280 ?
    __nla_put+0xc/0x20 ? cpumask_next_and+0x20/0x30 ? update_sd_lb_stats.constprop.144+0xd3/0x820 ?
    _raw_spin_unlock_irqrestore+0x25/0x37 ? __wake_up_common_lock+0x87/0xc0 ?
    kmem_cache_alloc_trace+0x3d/0x3d0 rtnl_newlink+0x43/0x60 The issue happens when the shift that should have
    been a function of the txq item size mistakenly used the ring size. Fix by using the item size.
    (CVE-2022-48729)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/20");
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
