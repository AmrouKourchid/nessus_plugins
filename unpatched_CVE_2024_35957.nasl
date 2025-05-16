#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228713);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35957");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35957");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: iommu/vt-d: Fix WARN_ON in iommu probe
    path Commit 1a75cc710b95 (iommu/vt-d: Use rbtree to track iommu probed devices) adds all devices probed
    by the iommu driver in a rbtree indexed by the source ID of each device. It assumes that each device has a
    unique source ID. This assumption is incorrect and the VT-d spec doesn't state this requirement either.
    The reason for using a rbtree to track devices is to look up the device with PCI bus and devfunc in the
    paths of handling ATS invalidation time out error and the PRI I/O page faults. Both are PCI ATS feature
    related. Only track the devices that have PCI ATS capabilities in the rbtree to avoid unnecessary WARN_ON
    in the iommu probe path. Otherwise, on some platforms below kernel splat will be displayed and the iommu
    probe results in failure. WARNING: CPU: 3 PID: 166 at drivers/iommu/intel/iommu.c:158
    intel_iommu_probe_device+0x319/0xd90 Call Trace: <TASK> ? __warn+0x7e/0x180 ?
    intel_iommu_probe_device+0x319/0xd90 ? report_bug+0x1f8/0x200 ? handle_bug+0x3c/0x70 ?
    exc_invalid_op+0x18/0x70 ? asm_exc_invalid_op+0x1a/0x20 ? intel_iommu_probe_device+0x319/0xd90 ?
    debug_mutex_init+0x37/0x50 __iommu_probe_device+0xf2/0x4f0 iommu_probe_device+0x22/0x70
    iommu_bus_notifier+0x1e/0x40 notifier_call_chain+0x46/0x150 blocking_notifier_call_chain+0x42/0x60
    bus_notify+0x2f/0x50 device_add+0x5ed/0x7e0 platform_device_add+0xf5/0x240 mfd_add_devices+0x3f9/0x500 ?
    preempt_count_add+0x4c/0xa0 ? up_write+0xa2/0x1b0 ? __debugfs_create_file+0xe3/0x150
    intel_lpss_probe+0x49f/0x5b0 ? pci_conf1_write+0xa3/0xf0 intel_lpss_pci_probe+0xcf/0x110 [intel_lpss_pci]
    pci_device_probe+0x95/0x120 really_probe+0xd9/0x370 ? __pfx___driver_attach+0x10/0x10
    __driver_probe_device+0x73/0x150 driver_probe_device+0x19/0xa0 __driver_attach+0xb6/0x180 ?
    __pfx___driver_attach+0x10/0x10 bus_for_each_dev+0x77/0xd0 bus_add_driver+0x114/0x210
    driver_register+0x5b/0x110 ? __pfx_intel_lpss_pci_driver_init+0x10/0x10 [intel_lpss_pci]
    do_one_initcall+0x57/0x2b0 ? kmalloc_trace+0x21e/0x280 ? do_init_module+0x1e/0x210
    do_init_module+0x5f/0x210 load_module+0x1d37/0x1fc0 ? init_module_from_file+0x86/0xd0
    init_module_from_file+0x86/0xd0 idempotent_init_module+0x17c/0x230 __x64_sys_finit_module+0x56/0xb0
    do_syscall_64+0x6e/0x140 entry_SYSCALL_64_after_hwframe+0x71/0x79 (CVE-2024-35957)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/20");
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
