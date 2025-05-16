#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228947);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36919");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36919");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: bnx2fc: Remove spin_lock_bh
    while releasing resources after upload The session resources are used by FW and driver when session is
    offloaded, once session is uploaded these resources are not used. The lock is not required as these fields
    won't be used any longer. The offload and upload calls are sequential, hence lock is not required. This
    will suppress following BUG_ON(): [ 449.843143] ------------[ cut here ]------------ [ 449.848302] kernel
    BUG at mm/vmalloc.c:2727! [ 449.853072] invalid opcode: 0000 [#1] PREEMPT SMP PTI [ 449.858712] CPU: 5
    PID: 1996 Comm: kworker/u24:2 Not tainted 5.14.0-118.el9.x86_64 #1 Rebooting. [ 449.867454] Hardware name:
    Dell Inc. PowerEdge R730/0WCJNT, BIOS 2.3.4 11/08/2016 [ 449.876966] Workqueue: fc_rport_eq fc_rport_work
    [libfc] [ 449.882910] RIP: 0010:vunmap+0x2e/0x30 [ 449.887098] Code: 00 65 8b 05 14 a2 f0 4a a9 00 ff ff
    00 75 1b 55 48 89 fd e8 34 36 79 00 48 85 ed 74 0b 48 89 ef 31 f6 5d e9 14 fc ff ff 5d c3 <0f> 0b 0f 1f 44
    00 00 41 57 41 56 49 89 ce 41 55 49 89 fd 41 54 41 [ 449.908054] RSP: 0018:ffffb83d878b3d68 EFLAGS:
    00010206 [ 449.913887] RAX: 0000000080000201 RBX: ffff8f4355133550 RCX: 000000000d400005 [ 449.921843]
    RDX: 0000000000000001 RSI: 0000000000001000 RDI: ffffb83da53f5000 [ 449.929808] RBP: ffff8f4ac6675800 R08:
    ffffb83d878b3d30 R09: 00000000000efbdf [ 449.937774] R10: 0000000000000003 R11: ffff8f434573e000 R12:
    0000000000001000 [ 449.945736] R13: 0000000000001000 R14: ffffb83da53f5000 R15: ffff8f43d4ea3ae0 [
    449.953701] FS: 0000000000000000(0000) GS:ffff8f529fc80000(0000) knlGS:0000000000000000 [ 449.962732] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 449.969138] CR2: 00007f8cf993e150 CR3: 0000000efbe10003
    CR4: 00000000003706e0 [ 449.977102] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [
    449.985065] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 449.993028] Call Trace: [
    449.995756] __iommu_dma_free+0x96/0x100 [ 450.000139] bnx2fc_free_session_resc+0x67/0x240 [bnx2fc] [
    450.006171] bnx2fc_upload_session+0xce/0x100 [bnx2fc] [ 450.011910] bnx2fc_rport_event_handler+0x9f/0x240
    [bnx2fc] [ 450.018136] fc_rport_work+0x103/0x5b0 [libfc] [ 450.023103] process_one_work+0x1e8/0x3c0 [
    450.027581] worker_thread+0x50/0x3b0 [ 450.031669] ? rescuer_thread+0x370/0x370 [ 450.036143]
    kthread+0x149/0x170 [ 450.039744] ? set_kthread_struct+0x40/0x40 [ 450.044411] ret_from_fork+0x22/0x30 [
    450.048404] Modules linked in: vfat msdos fat xfs nfs_layout_nfsv41_files rpcsec_gss_krb5 auth_rpcgss
    nfsv4 dns_resolver dm_service_time qedf qed crc8 bnx2fc libfcoe libfc scsi_transport_fc intel_rapl_msr
    intel_rapl_common x86_pkg_temp_thermal intel_powerclamp dcdbas rapl intel_cstate intel_uncore mei_me
    pcspkr mei ipmi_ssif lpc_ich ipmi_si fuse zram ext4 mbcache jbd2 loop nfsv3 nfs_acl nfs lockd grace
    fscache netfs irdma ice sd_mod t10_pi sg ib_uverbs ib_core 8021q garp mrp stp llc mgag200 i2c_algo_bit
    drm_kms_helper syscopyarea sysfillrect sysimgblt mxm_wmi fb_sys_fops cec crct10dif_pclmul ahci
    crc32_pclmul bnx2x drm ghash_clmulni_intel libahci rfkill i40e libata megaraid_sas mdio wmi sunrpc lrw
    dm_crypt dm_round_robin dm_multipath dm_snapshot dm_bufio dm_mirror dm_region_hash dm_log dm_zero dm_mod
    linear raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_tx raid6_pq libcrc32c
    crc32c_intel raid1 raid0 iscsi_ibft squashfs be2iscsi bnx2i cnic uio cxgb4i cxgb4 tls [ 450.048497]
    libcxgbi libcxgb qla4xxx iscsi_boot_sysfs iscsi_tcp libiscsi_tcp libiscsi scsi_transport_iscsi edd
    ipmi_devintf ipmi_msghandler [ 450.159753] ---[ end trace 712de2c57c64abc8 ]--- (CVE-2024-36919)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
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
  },
  {
   "product": {
    "name": "kernel",
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
