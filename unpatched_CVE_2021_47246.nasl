#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229793);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47246");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47246");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Fix page reclaim for dead
    peer hairpin When adding a hairpin flow, a firmware-side send queue is created for the peer net device,
    which claims some host memory pages for its internal ring buffer. If the peer net device is
    removed/unbound before the hairpin flow is deleted, then the send queue is not destroyed which leads to a
    stack trace on pci device remove: [ 748.005230] mlx5_core 0000:08:00.2: wait_func:1094:(pid 12985):
    MANAGE_PAGES(0x108) timeout. Will cause a leak of a command resource [ 748.005231] mlx5_core 0000:08:00.2:
    reclaim_pages:514:(pid 12985): failed reclaiming pages: err -110 [ 748.001835] mlx5_core 0000:08:00.2:
    mlx5_reclaim_root_pages:653:(pid 12985): failed reclaiming pages (-110) for func id 0x0 [ 748.002171]
    ------------[ cut here ]------------ [ 748.001177] FW pages counter is 4 after reclaiming all pages [
    748.001186] WARNING: CPU: 1 PID: 12985 at drivers/net/ethernet/mellanox/mlx5/core/pagealloc.c:685
    mlx5_reclaim_startup_pages+0x34b/0x460 [mlx5_core] [ +0.002771] Modules linked in: cls_flower mlx5_ib
    mlx5_core ptp pps_core act_mirred sch_ingress openvswitch nsh xt_conntrack xt_MASQUERADE
    nf_conntrack_netlink nfnetlink xt_addrtype iptable_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4
    br_netfilter rpcrdma rdma_ucm ib_iser libiscsi scsi_transport_iscsi rdma_cm ib_umad ib_ipoib iw_cm ib_cm
    ib_uverbs ib_core overlay fuse [last unloaded: pps_core] [ 748.007225] CPU: 1 PID: 12985 Comm: tee Not
    tainted 5.12.0+ #1 [ 748.001376] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
    rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 [ 748.002315] RIP:
    0010:mlx5_reclaim_startup_pages+0x34b/0x460 [mlx5_core] [ 748.001679] Code: 28 00 00 00 0f 85 22 01 00 00
    48 81 c4 b0 00 00 00 31 c0 5b 5d 41 5c 41 5d 41 5e 41 5f c3 48 c7 c7 40 cc 19 a1 e8 9f 71 0e e2 <0f> 0b e9
    30 ff ff ff 48 c7 c7 a0 cc 19 a1 e8 8c 71 0e e2 0f 0b e9 [ 748.003781] RSP: 0018:ffff88815220faf8 EFLAGS:
    00010286 [ 748.001149] RAX: 0000000000000000 RBX: ffff8881b4900280 RCX: 0000000000000000 [ 748.001445]
    RDX: 0000000000000027 RSI: 0000000000000004 RDI: ffffed102a441f51 [ 748.001614] RBP: 00000000000032b9 R08:
    0000000000000001 R09: ffffed1054a15ee8 [ 748.001446] R10: ffff8882a50af73b R11: ffffed1054a15ee7 R12:
    fffffbfff07c1e30 [ 748.001447] R13: dffffc0000000000 R14: ffff8881b492cba8 R15: 0000000000000000 [
    748.001429] FS: 00007f58bd08b580(0000) GS:ffff8882a5080000(0000) knlGS:0000000000000000 [ 748.001695] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 748.001309] CR2: 000055a026351740 CR3: 00000001d3b48006
    CR4: 0000000000370ea0 [ 748.001506] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [
    748.001483] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 748.001654] Call Trace: [
    748.000576] ? mlx5_satisfy_startup_pages+0x290/0x290 [mlx5_core] [ 748.001416] ?
    mlx5_cmd_teardown_hca+0xa2/0xd0 [mlx5_core] [ 748.001354] ? mlx5_cmd_init_hca+0x280/0x280 [mlx5_core] [
    748.001203] mlx5_function_teardown+0x30/0x60 [mlx5_core] [ 748.001275] mlx5_uninit_one+0xa7/0xc0
    [mlx5_core] [ 748.001200] remove_one+0x5f/0xc0 [mlx5_core] [ 748.001075] pci_device_remove+0x9f/0x1d0 [
    748.000833] device_release_driver_internal+0x1e0/0x490 [ 748.001207] unbind_store+0x19f/0x200 [
    748.000942] ? sysfs_file_ops+0x170/0x170 [ 748.001000] kernfs_fop_write_iter+0x2bc/0x450 [ 748.000970]
    new_sync_write+0x373/0x610 [ 748.001124] ? new_sync_read+0x600/0x600 [ 748.001057] ?
    lock_acquire+0x4d6/0x700 [ 748.000908] ? lockdep_hardirqs_on_prepare+0x400/0x400 [ 748.001126] ?
    fd_install+0x1c9/0x4d0 [ 748.000951] vfs_write+0x4d0/0x800 [ 748.000804] ksys_write+0xf9/0x1d0 [
    748.000868] ? __x64_sys_read+0xb0/0xb0 [ 748.000811] ? filp_open+0x50/0x50 [ 748.000919] ?
    syscall_enter_from_user_mode+0x1d/0x50 [ 748.001223] do_syscall_64+0x3f/0x80 [ 748.000892]
    entry_SYSCALL_64_after_hwframe+0x44/0xae [ 748.00 ---truncated--- (CVE-2021-47246)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47246");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
