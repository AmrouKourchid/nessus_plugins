#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229865);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47266");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47266");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RDMA/ipoib: Fix warning caused by
    destroying non-initial netns After the commit 5ce2dced8e95 (RDMA/ipoib: Set rtnl_link_ops for ipoib
    interfaces), if the IPoIB device is moved to non-initial netns, destroying that netns lets the device
    vanish instead of moving it back to the initial netns, This is happening because default_device_exit()
    skips the interfaces due to having rtnl_link_ops set. Steps to reporoduce: ip netns add foo ip link set
    mlx5_ib0 netns foo ip netns delete foo WARNING: CPU: 1 PID: 704 at net/core/dev.c:11435
    netdev_exit+0x3f/0x50 Modules linked in: xt_CHECKSUM xt_MASQUERADE xt_conntrack ipt_REJECT nf_reject_ipv4
    nft_compat nft_counter nft_chain_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 nf_tables nfnetlink
    tun d fuse CPU: 1 PID: 704 Comm: kworker/u64:3 Tainted: G S W 5.13.0-rc1+ #1 Hardware name: Dell Inc.
    PowerEdge R630/02C2CP, BIOS 2.1.5 04/11/2016 Workqueue: netns cleanup_net RIP: 0010:netdev_exit+0x3f/0x50
    Code: 48 8b bb 30 01 00 00 e8 ef 81 b1 ff 48 81 fb c0 3a 54 a1 74 13 48 8b 83 90 00 00 00 48 81 c3 90 00
    00 00 48 39 d8 75 02 5b c3 <0f> 0b 5b c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 0f 1f 44 00 RSP:
    0018:ffffb297079d7e08 EFLAGS: 00010206 RAX: ffff8eb542c00040 RBX: ffff8eb541333150 RCX: 000000008010000d
    RDX: 000000008010000e RSI: 000000008010000d RDI: ffff8eb440042c00 RBP: ffffb297079d7e48 R08:
    0000000000000001 R09: ffffffff9fdeac00 R10: ffff8eb5003be000 R11: 0000000000000001 R12: ffffffffa1545620
    R13: ffffffffa1545628 R14: 0000000000000000 R15: ffffffffa1543b20 FS: 0000000000000000(0000)
    GS:ffff8ed37fa00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00005601b5f4c2e8 CR3: 0000001fc8c10002 CR4: 00000000003706e0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace:
    ops_exit_list.isra.9+0x36/0x70 cleanup_net+0x234/0x390 process_one_work+0x1cb/0x360 ?
    process_one_work+0x360/0x360 worker_thread+0x30/0x370 ? process_one_work+0x360/0x360 kthread+0x116/0x130 ?
    kthread_park+0x80/0x80 ret_from_fork+0x22/0x30 To avoid the above warning and later on the kernel panic
    that could happen on shutdown due to a NULL pointer dereference, make sure to set the netns_refund flag
    that was introduced by commit 3a5ca857079e (can: dev: Move device back to init netns on owning netns
    delete) to properly restore the IPoIB interfaces to the initial netns. (CVE-2021-47266)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47266");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
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
