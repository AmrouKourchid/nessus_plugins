#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229483);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35927");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35927");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm: Check output polling initialized
    before disabling In drm_kms_helper_poll_disable() check if output polling support is initialized before
    disabling polling. If not flag this as a warning. Additionally in drm_mode_config_helper_suspend() and
    drm_mode_config_helper_resume() calls, that re the callers of these functions, avoid invoking them if
    polling is not initialized. For drivers like hyperv-drm, that do not initialize connector polling, if
    suspend is called without this check, it leads to suspend failure with following stack [ 770.719392]
    Freezing remaining freezable tasks ... (elapsed 0.001 seconds) done. [ 770.720592] printk: Suspending
    console(s) (use no_console_suspend to debug) [ 770.948823] ------------[ cut here ]------------ [
    770.948824] WARNING: CPU: 1 PID: 17197 at kernel/workqueue.c:3162 __flush_work.isra.0+0x212/0x230 [
    770.948831] Modules linked in: rfkill nft_counter xt_conntrack xt_owner udf nft_compat crc_itu_t
    nft_fib_inet nft_fib_ipv4 nft_fib_ipv6 nft_fib nft_reject_inet nf_reject_ipv4 nf_reject_ipv6 nft_reject
    nft_ct nft_chain_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 ip_set nf_tables nfnetlink vfat fat
    mlx5_ib ib_uverbs ib_core mlx5_core intel_rapl_msr intel_rapl_common kvm_amd ccp mlxfw kvm psample
    hyperv_drm tls drm_shmem_helper drm_kms_helper irqbypass pcspkr syscopyarea sysfillrect sysimgblt
    hv_balloon hv_utils joydev drm fuse xfs libcrc32c pci_hyperv pci_hyperv_intf sr_mod sd_mod cdrom t10_pi sg
    hv_storvsc scsi_transport_fc hv_netvsc serio_raw hyperv_keyboard hid_hyperv crct10dif_pclmul crc32_pclmul
    crc32c_intel hv_vmbus ghash_clmulni_intel dm_mirror dm_region_hash dm_log dm_mod [ 770.948863] CPU: 1 PID:
    17197 Comm: systemd-sleep Not tainted 5.14.0-362.2.1.el9_3.x86_64 #1 [ 770.948865] Hardware name:
    Microsoft Corporation Virtual Machine/Virtual Machine, BIOS Hyper-V UEFI Release v4.1 05/09/2022 [
    770.948866] RIP: 0010:__flush_work.isra.0+0x212/0x230 [ 770.948869] Code: 8b 4d 00 4c 8b 45 08 89 ca 48 c1
    e9 04 83 e2 08 83 e1 0f 83 ca 02 89 c8 48 0f ba 6d 00 03 e9 25 ff ff ff 0f 0b e9 4e ff ff ff <0f> 0b 45 31
    ed e9 44 ff ff ff e8 8f 89 b2 00 66 66 2e 0f 1f 84 00 [ 770.948870] RSP: 0018:ffffaf4ac213fb10 EFLAGS:
    00010246 [ 770.948871] RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffffffff8c992857 [ 770.948872]
    RDX: 0000000000000001 RSI: 0000000000000001 RDI: ffff9aad82b00330 [ 770.948873] RBP: ffff9aad82b00330 R08:
    0000000000000000 R09: ffff9aad87ee3d10 [ 770.948874] R10: 0000000000000200 R11: 0000000000000000 R12:
    ffff9aad82b00330 [ 770.948874] R13: 0000000000000001 R14: 0000000000000000 R15: 0000000000000001 [
    770.948875] FS: 00007ff1b2f6bb40(0000) GS:ffff9aaf37d00000(0000) knlGS:0000000000000000 [ 770.948878] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 770.948878] CR2: 0000555f345cb666 CR3: 00000001462dc005
    CR4: 0000000000370ee0 [ 770.948879] Call Trace: [ 770.948880] <TASK> [ 770.948881] ?
    show_trace_log_lvl+0x1c4/0x2df [ 770.948884] ? show_trace_log_lvl+0x1c4/0x2df [ 770.948886] ?
    __cancel_work_timer+0x103/0x190 [ 770.948887] ? __flush_work.isra.0+0x212/0x230 [ 770.948889] ?
    __warn+0x81/0x110 [ 770.948891] ? __flush_work.isra.0+0x212/0x230 [ 770.948892] ? report_bug+0x10a/0x140 [
    770.948895] ? handle_bug+0x3c/0x70 [ 770.948898] ? exc_invalid_op+0x14/0x70 [ 770.948899] ?
    asm_exc_invalid_op+0x16/0x20 [ 770.948903] ? __flush_work.isra.0+0x212/0x230 [ 770.948905]
    __cancel_work_timer+0x103/0x190 [ 770.948907] ? _raw_spin_unlock_irqrestore+0xa/0x30 [ 770.948910]
    drm_kms_helper_poll_disable+0x1e/0x40 [drm_kms_helper] [ 770.948923]
    drm_mode_config_helper_suspend+0x1c/0x80 [drm_kms_helper] [ 770.948933] ? __pfx_vmbus_suspend+0x10/0x10
    [hv_vmbus] [ 770.948942] hyperv_vmbus_suspend+0x17/0x40 [hyperv_drm] [ 770.948944] ?
    __pfx_vmbus_suspend+0x10/0x10 [hv_vmbus] [ 770.948951] dpm_run_callback+0x4c/0x140 [ 770.948954]
    __device_suspend_noir ---truncated--- (CVE-2024-35927)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35927");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-ibm",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
    ],
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
