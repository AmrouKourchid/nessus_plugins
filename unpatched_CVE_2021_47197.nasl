#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229778);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47197");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47197");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: nullify cq->dbg pointer in
    mlx5_debug_cq_remove() Prior to this patch in case mlx5_core_destroy_cq() failed it proceeds to rest of
    destroy operations. mlx5_core_destroy_cq() could be called again by user and cause additional call of
    mlx5_debug_cq_remove(). cq->dbg was not nullify in previous call and cause the crash. Fix it by nullify
    cq->dbg pointer after removal. Also proceed to destroy operations only if FW return 0 for
    MLX5_CMD_OP_DESTROY_CQ command. general protection fault, probably for non-canonical address
    0x2000300004058: 0000 [#1] SMP PTI CPU: 5 PID: 1228 Comm: python Not tainted
    5.15.0-rc5_for_upstream_min_debug_2021_10_14_11_06 #1 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
    BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 RIP: 0010:lockref_get+0x1/0x60 Code: 5d e9 53
    ff ff ff 48 8d 7f 70 e8 0a 2e 48 00 c7 85 d0 00 00 00 02 00 00 00 c6 45 70 00 fb 5d c3 c3 cc cc cc cc cc
    cc cc cc 53 <48> 8b 17 48 89 fb 85 d2 75 3d 48 89 d0 bf 64 00 00 00 48 89 c1 48 RSP: 0018:ffff888137dd7a38
    EFLAGS: 00010206 RAX: 0000000000000000 RBX: ffff888107d5f458 RCX: 00000000fffffffe RDX: 000000000002c2b0
    RSI: ffffffff8155e2e0 RDI: 0002000300004058 RBP: ffff888137dd7a88 R08: 0002000300004058 R09:
    ffff8881144a9f88 R10: 0000000000000000 R11: 0000000000000000 R12: ffff8881141d4000 R13: ffff888137dd7c68
    R14: ffff888137dd7d58 R15: ffff888137dd7cc0 FS: 00007f4644f2a4c0(0000) GS:ffff8887a2d40000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000055b4500f4380 CR3:
    0000000114f7a003 CR4: 0000000000170ea0 Call Trace: simple_recursive_removal+0x33/0x2e0 ?
    debugfs_remove+0x60/0x60 debugfs_remove+0x40/0x60 mlx5_debug_cq_remove+0x32/0x70 [mlx5_core]
    mlx5_core_destroy_cq+0x41/0x1d0 [mlx5_core] devx_obj_cleanup+0x151/0x330 [mlx5_ib] ? __pollwait+0xd0/0xd0
    ? xas_load+0x5/0x70 ? xa_load+0x62/0xa0 destroy_hw_idr_uobject+0x20/0x80 [ib_uverbs]
    uverbs_destroy_uobject+0x3b/0x360 [ib_uverbs] uobj_destroy+0x54/0xa0 [ib_uverbs]
    ib_uverbs_cmd_verbs+0xaf2/0x1160 [ib_uverbs] ? uverbs_finalize_object+0xd0/0xd0 [ib_uverbs]
    ib_uverbs_ioctl+0xc4/0x1b0 [ib_uverbs] __x64_sys_ioctl+0x3e4/0x8e0 (CVE-2021-47197)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47197");

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
