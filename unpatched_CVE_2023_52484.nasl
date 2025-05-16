#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227075);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52484");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52484");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: iommu/arm-smmu-v3: Fix soft lockup
    triggered by arm_smmu_mm_invalidate_range When running an SVA case, the following soft lockup is
    triggered: -------------------------------------------------------------------- watchdog: BUG: soft lockup
    - CPU#244 stuck for 26s! pstate: 83400009 (Nzcv daif +PAN -UAO +TCO +DIT -SSBS BTYPE=--) pc :
    arm_smmu_cmdq_issue_cmdlist+0x178/0xa50 lr : arm_smmu_cmdq_issue_cmdlist+0x150/0xa50 sp : ffff8000d83ef290
    x29: ffff8000d83ef290 x28: 000000003b9aca00 x27: 0000000000000000 x26: ffff8000d83ef3c0 x25:
    da86c0812194a0e8 x24: 0000000000000000 x23: 0000000000000040 x22: ffff8000d83ef340 x21: ffff0000c63980c0
    x20: 0000000000000001 x19: ffff0000c6398080 x18: 0000000000000000 x17: 0000000000000000 x16:
    0000000000000000 x15: ffff3000b4a3bbb0 x14: ffff3000b4a30888 x13: ffff3000b4a3cf60 x12: 0000000000000000
    x11: 0000000000000000 x10: 0000000000000000 x9 : ffffc08120e4d6bc x8 : 0000000000000000 x7 :
    0000000000000000 x6 : 0000000000048cfa x5 : 0000000000000000 x4 : 0000000000000001 x3 : 000000000000000a
    x2 : 0000000080000000 x1 : 0000000000000000 x0 : 0000000000000001 Call trace:
    arm_smmu_cmdq_issue_cmdlist+0x178/0xa50 __arm_smmu_tlb_inv_range+0x118/0x254
    arm_smmu_tlb_inv_range_asid+0x6c/0x130 arm_smmu_mm_invalidate_range+0xa0/0xa4
    __mmu_notifier_invalidate_range_end+0x88/0x120 unmap_vmas+0x194/0x1e0 unmap_region+0xb4/0x144
    do_mas_align_munmap+0x290/0x490 do_mas_munmap+0xbc/0x124 __vm_munmap+0xa8/0x19c
    __arm64_sys_munmap+0x28/0x50 invoke_syscall+0x78/0x11c el0_svc_common.constprop.0+0x58/0x1c0
    do_el0_svc+0x34/0x60 el0_svc+0x2c/0xd4 el0t_64_sync_handler+0x114/0x140 el0t_64_sync+0x1a4/0x1a8
    -------------------------------------------------------------------- Note that since 6.6-rc1 the
    arm_smmu_mm_invalidate_range above is renamed to arm_smmu_mm_arch_invalidate_secondary_tlbs, yet the
    problem remains. The commit 06ff87bae8d3 (arm64: mm: remove unused functions and variable protoypes)
    fixed a similar lockup on the CPU MMU side. Yet, it can occur to SMMU too, since
    arm_smmu_mm_arch_invalidate_secondary_tlbs() is called typically next to MMU tlb flush function, e.g.
    tlb_flush_mmu_tlbonly { tlb_flush { __flush_tlb_range { // check MAX_TLBI_OPS } }
    mmu_notifier_arch_invalidate_secondary_tlbs { arm_smmu_mm_arch_invalidate_secondary_tlbs { // does not
    check MAX_TLBI_OPS } } } Clone a CMDQ_MAX_TLBI_OPS from the MAX_TLBI_OPS in tlbflush.h, since in an SVA
    case SMMU uses the CPU page table, so it makes sense to align with the tlbflush code. Then, replace per-
    page TLBI commands with a single per-asid TLBI command, if the request size hits this threshold.
    (CVE-2023-52484)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
