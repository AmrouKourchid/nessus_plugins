#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228941);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36884");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36884");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: iommu/arm-smmu: Use the correct type
    in nvidia_smmu_context_fault() This was missed because of the function pointer indirection.
    nvidia_smmu_context_fault() is also installed as a irq function, and the 'void *' was changed to a struct
    arm_smmu_domain. Since the iommu_domain is embedded at a non-zero offset this causes
    nvidia_smmu_context_fault() to miscompute the offset. Fixup the types. Unable to handle kernel NULL
    pointer dereference at virtual address 0000000000000120 Mem abort info: ESR = 0x0000000096000004 EC =
    0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x04: level 0 translation
    fault Data abort info: ISV = 0, ISS = 0x00000004, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess =
    0 GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 user pgtable: 4k pages, 48-bit VAs, pgdp=0000000107c9f000
    [0000000000000120] pgd=0000000000000000, p4d=0000000000000000 Internal error: Oops: 0000000096000004 [#1]
    SMP Modules linked in: CPU: 1 PID: 47 Comm: kworker/u25:0 Not tainted 6.9.0-0.rc7.58.eln136.aarch64 #1
    Hardware name: Unknown NVIDIA Jetson Orin NX/NVIDIA Jetson Orin NX, BIOS 3.1-32827747 03/19/2023
    Workqueue: events_unbound deferred_probe_work_func pstate: 604000c9 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS
    BTYPE=--) pc : nvidia_smmu_context_fault+0x1c/0x158 lr : __free_irq+0x1d4/0x2e8 sp : ffff80008044b6f0 x29:
    ffff80008044b6f0 x28: ffff000080a60b18 x27: ffffd32b5172e970 x26: 0000000000000000 x25: ffff0000802f5aac
    x24: ffff0000802f5a30 x23: ffff0000802f5b60 x22: 0000000000000057 x21: 0000000000000000 x20:
    ffff0000802f5a00 x19: ffff000087d4cd80 x18: ffffffffffffffff x17: 6234362066666666 x16: 6630303078302d30
    x15: ffff00008156d888 x14: 0000000000000000 x13: ffff0000801db910 x12: ffff00008156d6d0 x11:
    0000000000000003 x10: ffff0000801db918 x9 : ffffd32b50f94d9c x8 : 1fffe0001032fda1 x7 : ffff00008197ed00
    x6 : 000000000000000f x5 : 000000000000010e x4 : 000000000000010e x3 : 0000000000000000 x2 :
    ffffd32b51720cd8 x1 : ffff000087e6f700 x0 : 0000000000000057 Call trace:
    nvidia_smmu_context_fault+0x1c/0x158 __free_irq+0x1d4/0x2e8 free_irq+0x3c/0x80 devm_free_irq+0x64/0xa8
    arm_smmu_domain_free+0xc4/0x158 iommu_domain_free+0x44/0xa0 iommu_deinit_device+0xd0/0xf8
    __iommu_group_remove_device+0xcc/0xe0 iommu_bus_notifier+0x64/0xa8 notifier_call_chain+0x78/0x148
    blocking_notifier_call_chain+0x4c/0x90 bus_notify+0x44/0x70 device_del+0x264/0x3e8
    pci_remove_bus_device+0x84/0x120 pci_remove_root_bus+0x5c/0xc0 dw_pcie_host_deinit+0x38/0xe0
    tegra_pcie_config_rp+0xc0/0x1f0 tegra_pcie_dw_probe+0x34c/0x700 platform_probe+0x70/0xe8
    really_probe+0xc8/0x3a0 __driver_probe_device+0x84/0x160 driver_probe_device+0x44/0x130
    __device_attach_driver+0xc4/0x170 bus_for_each_drv+0x90/0x100 __device_attach+0xa8/0x1c8
    device_initial_probe+0x1c/0x30 bus_probe_device+0xb0/0xc0 deferred_probe_work_func+0xbc/0x120
    process_one_work+0x194/0x490 worker_thread+0x284/0x3b0 kthread+0xf4/0x108 ret_from_fork+0x10/0x20 Code:
    a9b97bfd 910003fd a9025bf5 f85a0035 (b94122a1) (CVE-2024-36884)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36884");

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
