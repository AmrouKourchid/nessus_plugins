#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226919);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52743");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52743");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ice: Do not use WQ_MEM_RECLAIM flag
    for workqueue When both ice and the irdma driver are loaded, a warning in check_flush_dependency is being
    triggered. This is due to ice driver workqueue being allocated with the WQ_MEM_RECLAIM flag and the irdma
    one is not. According to kernel documentation, this flag should be set if the workqueue will be involved
    in the kernel's memory reclamation flow. Since it is not, there is no need for the ice driver's WQ to have
    this flag set so remove it. Example trace: [ +0.000004] workqueue: WQ_MEM_RECLAIM ice:ice_service_task
    [ice] is flushing !WQ_MEM_RECLAIM infiniband:0x0 [ +0.000139] WARNING: CPU: 0 PID: 728 at
    kernel/workqueue.c:2632 check_flush_dependency+0x178/0x1a0 [ +0.000011] Modules linked in: bonding tls
    xt_CHECKSUM xt_MASQUERADE xt_conntrack ipt_REJECT nf_reject_ipv4 nft_compat nft_cha in_nat nf_nat
    nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 nf_tables nfnetlink bridge stp llc rfkill vfat fat
    intel_rapl_msr intel _rapl_common isst_if_common skx_edac nfit libnvdimm x86_pkg_temp_thermal
    intel_powerclamp coretemp kvm_intel kvm irqbypass crct1 0dif_pclmul crc32_pclmul ghash_clmulni_intel rapl
    intel_cstate rpcrdma sunrpc rdma_ucm ib_srpt ib_isert iscsi_target_mod target_ core_mod ib_iser libiscsi
    scsi_transport_iscsi rdma_cm ib_cm iw_cm iTCO_wdt iTCO_vendor_support ipmi_ssif irdma mei_me ib_uverbs
    ib_core intel_uncore joydev pcspkr i2c_i801 acpi_ipmi mei lpc_ich i2c_smbus intel_pch_thermal ioatdma
    ipmi_si acpi_power_meter acpi_pad xfs libcrc32c sd_mod t10_pi crc64_rocksoft crc64 sg ahci ixgbe libahci
    ice i40e igb crc32c_intel mdio i2c_algo_bit liba ta dca wmi dm_mirror dm_region_hash dm_log dm_mod
    ipmi_devintf ipmi_msghandler fuse [ +0.000161] [last unloaded: bonding] [ +0.000006] CPU: 0 PID: 728 Comm:
    kworker/0:2 Tainted: G S 6.2.0-rc2_next-queue-13jan-00458-gc20aabd57164 #1 [ +0.000006] Hardware name:
    Intel Corporation S2600WFT/S2600WFT, BIOS SE5C620.86B.02.01.0010.010620200716 01/06/2020 [ +0.000003]
    Workqueue: ice ice_service_task [ice] [ +0.000127] RIP: 0010:check_flush_dependency+0x178/0x1a0 [
    +0.000005] Code: 89 8e 02 01 e8 49 3d 40 00 49 8b 55 18 48 8d 8d d0 00 00 00 48 8d b3 d0 00 00 00 4d 89 e0
    48 c7 c7 e0 3b 08 9f e8 bb d3 07 01 <0f> 0b e9 be fe ff ff 80 3d 24 89 8e 02 00 0f 85 6b ff ff ff e9 06 [
    +0.000004] RSP: 0018:ffff88810a39f990 EFLAGS: 00010282 [ +0.000005] RAX: 0000000000000000 RBX:
    ffff888141bc2400 RCX: 0000000000000000 [ +0.000004] RDX: 0000000000000001 RSI: dffffc0000000000 RDI:
    ffffffffa1213a80 [ +0.000003] RBP: ffff888194bf3400 R08: ffffed117b306112 R09: ffffed117b306112 [
    +0.000003] R10: ffff888bd983088b R11: ffffed117b306111 R12: 0000000000000000 [ +0.000003] R13:
    ffff888111f84d00 R14: ffff88810a3943ac R15: ffff888194bf3400 [ +0.000004] FS: 0000000000000000(0000)
    GS:ffff888bd9800000(0000) knlGS:0000000000000000 [ +0.000003] CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 [ +0.000003] CR2: 000056035b208b60 CR3: 000000017795e005 CR4: 00000000007706f0 [
    +0.000003] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [ +0.000003] DR3:
    0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ +0.000002] PKRU: 55555554 [ +0.000003] Call
    Trace: [ +0.000002] <TASK> [ +0.000003] __flush_workqueue+0x203/0x840 [ +0.000006] ?
    mutex_unlock+0x84/0xd0 [ +0.000008] ? __pfx_mutex_unlock+0x10/0x10 [ +0.000004] ?
    __pfx___flush_workqueue+0x10/0x10 [ +0.000006] ? mutex_lock+0xa3/0xf0 [ +0.000005]
    ib_cache_cleanup_one+0x39/0x190 [ib_core] [ +0.000174] __ib_unregister_device+0x84/0xf0 [ib_core] [
    +0.000094] ib_unregister_device+0x25/0x30 [ib_core] [ +0.000093] irdma_ib_unregister_device+0x97/0xc0
    [irdma] [ +0.000064] ? __pfx_irdma_ib_unregister_device+0x10/0x10 [irdma] [ +0.000059] ?
    up_write+0x5c/0x90 [ +0.000005] irdma_remove+0x36/0x90 [irdma] [ +0.000062] auxiliary_bus_remove+0x32/0x50
    [ +0.000007] device_r ---truncated--- (CVE-2023-52743)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52743");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
