#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225284);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48796");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48796");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: iommu: Fix potential use-after-free
    during probe Kasan has reported the following use after free on dev->iommu. when a device probe fails and
    it is in process of freeing dev->iommu in dev_iommu_free function, a deferred_probe_work_func runs in
    parallel and tries to access dev->iommu->fwspec in of_iommu_configure path thus causing use after free.
    BUG: KASAN: use-after-free in of_iommu_configure+0xb4/0x4a4 Read of size 8 at addr ffffff87a2f1acb8 by
    task kworker/u16:2/153 Workqueue: events_unbound deferred_probe_work_func Call trace:
    dump_backtrace+0x0/0x33c show_stack+0x18/0x24 dump_stack_lvl+0x16c/0x1e0
    print_address_description+0x84/0x39c __kasan_report+0x184/0x308 kasan_report+0x50/0x78
    __asan_load8+0xc0/0xc4 of_iommu_configure+0xb4/0x4a4 of_dma_configure_id+0x2fc/0x4d4
    platform_dma_configure+0x40/0x5c really_probe+0x1b4/0xb74 driver_probe_device+0x11c/0x228
    __device_attach_driver+0x14c/0x304 bus_for_each_drv+0x124/0x1b0 __device_attach+0x25c/0x334
    device_initial_probe+0x24/0x34 bus_probe_device+0x78/0x134 deferred_probe_work_func+0x130/0x1a8
    process_one_work+0x4c8/0x970 worker_thread+0x5c8/0xaec kthread+0x1f8/0x220 ret_from_fork+0x10/0x18
    Allocated by task 1: ____kasan_kmalloc+0xd4/0x114 __kasan_kmalloc+0x10/0x1c
    kmem_cache_alloc_trace+0xe4/0x3d4 __iommu_probe_device+0x90/0x394 probe_iommu_group+0x70/0x9c
    bus_for_each_dev+0x11c/0x19c bus_iommu_probe+0xb8/0x7d4 bus_set_iommu+0xcc/0x13c
    arm_smmu_bus_init+0x44/0x130 [arm_smmu] arm_smmu_device_probe+0xb88/0xc54 [arm_smmu]
    platform_drv_probe+0xe4/0x13c really_probe+0x2c8/0xb74 driver_probe_device+0x11c/0x228
    device_driver_attach+0xf0/0x16c __driver_attach+0x80/0x320 bus_for_each_dev+0x11c/0x19c
    driver_attach+0x38/0x48 bus_add_driver+0x1dc/0x3a4 driver_register+0x18c/0x244
    __platform_driver_register+0x88/0x9c init_module+0x64/0xff4 [arm_smmu] do_one_initcall+0x17c/0x2f0
    do_init_module+0xe8/0x378 load_module+0x3f80/0x4a40 __se_sys_finit_module+0x1a0/0x1e4
    __arm64_sys_finit_module+0x44/0x58 el0_svc_common+0x100/0x264 do_el0_svc+0x38/0xa4 el0_svc+0x20/0x30
    el0_sync_handler+0x68/0xac el0_sync+0x160/0x180 Freed by task 1: kasan_set_track+0x4c/0x84
    kasan_set_free_info+0x28/0x4c ____kasan_slab_free+0x120/0x15c __kasan_slab_free+0x18/0x28
    slab_free_freelist_hook+0x204/0x2fc kfree+0xfc/0x3a4 __iommu_probe_device+0x284/0x394
    probe_iommu_group+0x70/0x9c bus_for_each_dev+0x11c/0x19c bus_iommu_probe+0xb8/0x7d4
    bus_set_iommu+0xcc/0x13c arm_smmu_bus_init+0x44/0x130 [arm_smmu] arm_smmu_device_probe+0xb88/0xc54
    [arm_smmu] platform_drv_probe+0xe4/0x13c really_probe+0x2c8/0xb74 driver_probe_device+0x11c/0x228
    device_driver_attach+0xf0/0x16c __driver_attach+0x80/0x320 bus_for_each_dev+0x11c/0x19c
    driver_attach+0x38/0x48 bus_add_driver+0x1dc/0x3a4 driver_register+0x18c/0x244
    __platform_driver_register+0x88/0x9c init_module+0x64/0xff4 [arm_smmu] do_one_initcall+0x17c/0x2f0
    do_init_module+0xe8/0x378 load_module+0x3f80/0x4a40 __se_sys_finit_module+0x1a0/0x1e4
    __arm64_sys_finit_module+0x44/0x58 el0_svc_common+0x100/0x264 do_el0_svc+0x38/0xa4 el0_svc+0x20/0x30
    el0_sync_handler+0x68/0xac el0_sync+0x160/0x180 Fix this by setting dev->iommu to NULL first and then
    freeing dev_iommu structure in dev_iommu_free function. (CVE-2022-48796)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48796");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
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
