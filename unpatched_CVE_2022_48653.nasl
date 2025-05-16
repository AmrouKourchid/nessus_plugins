#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225179);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48653");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48653");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ice: Don't double unplug aux on peer
    initiated reset In the IDC callback that is accessed when the aux drivers request a reset, the function to
    unplug the aux devices is called. This function is also called in the ice_prepare_for_reset function. This
    double call is causing a scheduling while atomic BUG. [ 662.676430] ice 0000:4c:00.0 rocep76s0: cqp
    opcode = 0x1 maj_err_code = 0xffff min_err_code = 0x8003 [ 662.676609] ice 0000:4c:00.0 rocep76s0: [Modify
    QP Cmd Error][op_code=8] status=-29 waiting=1 completion_err=1 maj=0xffff min=0x8003 [ 662.815006] ice
    0000:4c:00.0 rocep76s0: ICE OICR event notification: oicr = 0x10000003 [ 662.815014] ice 0000:4c:00.0
    rocep76s0: critical PE Error, GLPE_CRITERR=0x00011424 [ 662.815017] ice 0000:4c:00.0 rocep76s0: Requesting
    a reset [ 662.815475] BUG: scheduling while atomic: swapper/37/0/0x00010002 [ 662.815475] BUG: scheduling
    while atomic: swapper/37/0/0x00010002 [ 662.815477] Modules linked in: rpcsec_gss_krb5 auth_rpcgss nfsv4
    dns_resolver nfs lockd grace fscache netfs rfkill 8021q garp mrp stp llc vfat fat rpcrdma intel_rapl_msr
    intel_rapl_common sunrpc i10nm_edac rdma_ucm nfit ib_srpt libnvdimm ib_isert iscsi_target_mod
    x86_pkg_temp_thermal intel_powerclamp coretemp target_core_mod snd_hda_intel ib_iser snd_intel_dspcfg
    libiscsi snd_intel_sdw_acpi scsi_transport_iscsi kvm_intel iTCO_wdt rdma_cm snd_hda_codec kvm iw_cm
    ipmi_ssif iTCO_vendor_support snd_hda_core irqbypass crct10dif_pclmul crc32_pclmul ghash_clmulni_intel
    snd_hwdep snd_seq snd_seq_device rapl snd_pcm snd_timer isst_if_mbox_pci pcspkr isst_if_mmio irdma
    intel_uncore idxd acpi_ipmi joydev isst_if_common snd mei_me idxd_bus ipmi_si soundcore i2c_i801 mei
    ipmi_devintf i2c_smbus i2c_ismt ipmi_msghandler acpi_power_meter acpi_pad rv(OE) ib_uverbs ib_cm ib_core
    xfs libcrc32c ast i2c_algo_bit drm_vram_helper drm_kms_helper syscopyarea sysfillrect sysimgblt
    fb_sys_fops drm_ttm_helpe r ttm [ 662.815546] nvme nvme_core ice drm crc32c_intel i40e t10_pi wmi
    pinctrl_emmitsburg dm_mirror dm_region_hash dm_log dm_mod fuse [ 662.815557] Preemption disabled at: [
    662.815558] [<0000000000000000>] 0x0 [ 662.815563] CPU: 37 PID: 0 Comm: swapper/37 Kdump: loaded Tainted:
    G S OE 5.17.1 #2 [ 662.815566] Hardware name: Intel Corporation D50DNP/D50DNP, BIOS
    SE5C6301.86B.6624.D18.2111021741 11/02/2021 [ 662.815568] Call Trace: [ 662.815572] <IRQ> [ 662.815574]
    dump_stack_lvl+0x33/0x42 [ 662.815581] __schedule_bug.cold.147+0x7d/0x8a [ 662.815588]
    __schedule+0x798/0x990 [ 662.815595] schedule+0x44/0xc0 [ 662.815597] schedule_preempt_disabled+0x14/0x20
    [ 662.815600] __mutex_lock.isra.11+0x46c/0x490 [ 662.815603] ? __ibdev_printk+0x76/0xc0 [ib_core] [
    662.815633] device_del+0x37/0x3d0 [ 662.815639] ice_unplug_aux_dev+0x1a/0x40 [ice] [ 662.815674]
    ice_schedule_reset+0x3c/0xd0 [ice] [ 662.815693] irdma_iidc_event_handler.cold.7+0xb6/0xd3 [irdma] [
    662.815712] ? bitmap_find_next_zero_area_off+0x45/0xa0 [ 662.815719] ice_send_event_to_aux+0x54/0x70 [ice]
    [ 662.815741] ice_misc_intr+0x21d/0x2d0 [ice] [ 662.815756] __handle_irq_event_percpu+0x4c/0x180 [
    662.815762] handle_irq_event_percpu+0xf/0x40 [ 662.815764] handle_irq_event+0x34/0x60 [ 662.815766]
    handle_edge_irq+0x9a/0x1c0 [ 662.815770] __common_interrupt+0x62/0x100 [ 662.815774]
    common_interrupt+0xb4/0xd0 [ 662.815779] </IRQ> [ 662.815780] <TASK> [ 662.815780]
    asm_common_interrupt+0x1e/0x40 [ 662.815785] RIP: 0010:cpuidle_enter_state+0xd6/0x380 [ 662.815789] Code:
    49 89 c4 0f 1f 44 00 00 31 ff e8 65 d7 95 ff 45 84 ff 74 12 9c 58 f6 c4 02 0f 85 64 02 00 00 31 ff e8 ae
    c5 9c ff fb 45 85 f6 <0f> 88 12 01 00 00 49 63 d6 4c 2b 24 24 48 8d 04 52 48 8d 04 82 49 [ 662.815791]
    RSP: 0018:ff2c2c4f18edbe80 EFLAGS: 00000202 [ 662.815793] RAX: ff280805df140000 RBX: 0000000000000002 RCX:
    000000000000001f [ 662.815795] RDX: 0000009a52da2d08 R ---truncated--- (CVE-2022-48653)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-gcp-5.15",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  },
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
