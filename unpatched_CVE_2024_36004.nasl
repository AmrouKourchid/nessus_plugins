#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228571);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36004");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36004");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: i40e: Do not use WQ_MEM_RECLAIM flag
    for workqueue Issue reported by customer during SRIOV testing, call trace: When both i40e and the i40iw
    driver are loaded, a warning in check_flush_dependency is being triggered. This seems to be because of the
    i40e driver workqueue is allocated with the WQ_MEM_RECLAIM flag, and the i40iw one is not. Similar error
    was encountered on ice too and it was fixed by removing the flag. Do the same for i40e too. [Feb 9 09:08]
    ------------[ cut here ]------------ [ +0.000004] workqueue: WQ_MEM_RECLAIM i40e:i40e_service_task [i40e]
    is flushing !WQ_MEM_RECLAIM infiniband:0x0 [ +0.000060] WARNING: CPU: 0 PID: 937 at
    kernel/workqueue.c:2966 check_flush_dependency+0x10b/0x120 [ +0.000007] Modules linked in: snd_seq_dummy
    snd_hrtimer snd_seq snd_timer snd_seq_device snd soundcore nls_utf8 cifs cifs_arc4 nls_ucs2_utils rdma_cm
    iw_cm ib_cm cifs_md4 dns_resolver netfs qrtr rfkill sunrpc vfat fat intel_rapl_msr intel_rapl_common irdma
    intel_uncore_frequency intel_uncore_frequency_common ice ipmi_ssif isst_if_common skx_edac nfit libnvdimm
    x86_pkg_temp_thermal intel_powerclamp gnss coretemp ib_uverbs rapl intel_cstate ib_core iTCO_wdt
    iTCO_vendor_support acpi_ipmi mei_me ipmi_si intel_uncore ioatdma i2c_i801 joydev pcspkr mei ipmi_devintf
    lpc_ich intel_pch_thermal i2c_smbus ipmi_msghandler acpi_power_meter acpi_pad xfs libcrc32c ast sd_mod
    drm_shmem_helper t10_pi drm_kms_helper sg ixgbe drm i40e ahci crct10dif_pclmul libahci crc32_pclmul igb
    crc32c_intel libata ghash_clmulni_intel i2c_algo_bit mdio dca wmi dm_mirror dm_region_hash dm_log dm_mod
    fuse [ +0.000050] CPU: 0 PID: 937 Comm: kworker/0:3 Kdump: loaded Not tainted 6.8.0-rc2-Feb-net_dev-
    Qiueue-00279-gbd43c5687e05 #1 [ +0.000003] Hardware name: Intel Corporation S2600BPB/S2600BPB, BIOS
    SE5C620.86B.02.01.0013.121520200651 12/15/2020 [ +0.000001] Workqueue: i40e i40e_service_task [i40e] [
    +0.000024] RIP: 0010:check_flush_dependency+0x10b/0x120 [ +0.000003] Code: ff 49 8b 54 24 18 48 8d 8b b0
    00 00 00 49 89 e8 48 81 c6 b0 00 00 00 48 c7 c7 b0 97 fa 9f c6 05 8a cc 1f 02 01 e8 35 b3 fd ff <0f> 0b e9
    10 ff ff ff 80 3d 78 cc 1f 02 00 75 94 e9 46 ff ff ff 90 [ +0.000002] RSP: 0018:ffffbd294976bcf8 EFLAGS:
    00010282 [ +0.000002] RAX: 0000000000000000 RBX: ffff94d4c483c000 RCX: 0000000000000027 [ +0.000001] RDX:
    ffff94d47f620bc8 RSI: 0000000000000001 RDI: ffff94d47f620bc0 [ +0.000001] RBP: 0000000000000000 R08:
    0000000000000000 R09: 00000000ffff7fff [ +0.000001] R10: ffffbd294976bb98 R11: ffffffffa0be65e8 R12:
    ffff94c5451ea180 [ +0.000001] R13: ffff94c5ab5e8000 R14: ffff94c5c20b6e05 R15: ffff94c5f1330ab0 [
    +0.000001] FS: 0000000000000000(0000) GS:ffff94d47f600000(0000) knlGS:0000000000000000 [ +0.000002] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ +0.000001] CR2: 00007f9e6f1fca70 CR3: 0000000038e20004 CR4:
    00000000007706f0 [ +0.000000] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [
    +0.000001] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ +0.000001] PKRU: 55555554 [
    +0.000001] Call Trace: [ +0.000001] <TASK> [ +0.000002] ? __warn+0x80/0x130 [ +0.000003] ?
    check_flush_dependency+0x10b/0x120 [ +0.000002] ? report_bug+0x195/0x1a0 [ +0.000005] ?
    handle_bug+0x3c/0x70 [ +0.000003] ? exc_invalid_op+0x14/0x70 [ +0.000002] ? asm_exc_invalid_op+0x16/0x20 [
    +0.000006] ? check_flush_dependency+0x10b/0x120 [ +0.000002] ? check_flush_dependency+0x10b/0x120 [
    +0.000002] __flush_workqueue+0x126/0x3f0 [ +0.000015] ib_cache_cleanup_one+0x1c/0xe0 [ib_core] [
    +0.000056] __ib_unregister_device+0x6a/0xb0 [ib_core] [ +0.000023] ib_unregister_device_and_put+0x34/0x50
    [ib_core] [ +0.000020] i40iw_close+0x4b/0x90 [irdma] [ +0.000022]
    i40e_notify_client_of_netdev_close+0x54/0xc0 [i40e] [ +0.000035] i40e_service_task+0x126/0x190 [i40e] [
    +0.000024] process_one_work+0x174/0x340 [ +0.000003] worker_th ---truncated--- (CVE-2024-36004)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36004");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/10");
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
