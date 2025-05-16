#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225380);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48935");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48935");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: unregister
    flowtable hooks on netns exit Unregister flowtable hooks before they are releases via
    nf_tables_flowtable_destroy() otherwise hook core reports UAF. BUG: KASAN: use-after-free in
    nf_hook_entries_grow+0x5a7/0x700 net/netfilter/core.c:142 net/netfilter/core.c:142 Read of size 4 at addr
    ffff8880736f7438 by task syz-executor579/3666 CPU: 0 PID: 3666 Comm: syz-executor579 Not tainted
    5.16.0-rc5-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google
    01/01/2011 Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline] __dump_stack lib/dump_stack.c:88
    [inline] lib/dump_stack.c:106 dump_stack_lvl+0x1dc/0x2d8 lib/dump_stack.c:106 lib/dump_stack.c:106
    print_address_description+0x65/0x380 mm/kasan/report.c:247 mm/kasan/report.c:247 __kasan_report
    mm/kasan/report.c:433 [inline] __kasan_report mm/kasan/report.c:433 [inline] mm/kasan/report.c:450
    kasan_report+0x19a/0x1f0 mm/kasan/report.c:450 mm/kasan/report.c:450 nf_hook_entries_grow+0x5a7/0x700
    net/netfilter/core.c:142 net/netfilter/core.c:142 __nf_register_net_hook+0x27e/0x8d0
    net/netfilter/core.c:429 net/netfilter/core.c:429 nf_register_net_hook+0xaa/0x180 net/netfilter/core.c:571
    net/netfilter/core.c:571 nft_register_flowtable_net_hooks+0x3c5/0x730 net/netfilter/nf_tables_api.c:7232
    net/netfilter/nf_tables_api.c:7232 nf_tables_newflowtable+0x2022/0x2cf0 net/netfilter/nf_tables_api.c:7430
    net/netfilter/nf_tables_api.c:7430 nfnetlink_rcv_batch net/netfilter/nfnetlink.c:513 [inline]
    nfnetlink_rcv_skb_batch net/netfilter/nfnetlink.c:634 [inline] nfnetlink_rcv_batch
    net/netfilter/nfnetlink.c:513 [inline] net/netfilter/nfnetlink.c:652 nfnetlink_rcv_skb_batch
    net/netfilter/nfnetlink.c:634 [inline] net/netfilter/nfnetlink.c:652 nfnetlink_rcv+0x10e6/0x2550
    net/netfilter/nfnetlink.c:652 net/netfilter/nfnetlink.c:652 __nft_release_hook() calls
    nft_unregister_flowtable_net_hooks() which only unregisters the hooks, then after RCU grace period, it is
    guaranteed that no packets add new entries to the flowtable (no flow offload rules and flowtable hooks are
    reachable from packet path), so it is safe to call nf_flow_table_free() which cleans up the remaining
    entries from the flowtable (both software and hardware) and it unbinds the flow_block. (CVE-2022-48935)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
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
