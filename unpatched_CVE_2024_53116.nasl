#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231954);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53116");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53116");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/panthor: Fix handling of partial
    GPU mapping of BOs This commit fixes the bug in the handling of partial mapping of the buffer objects to
    the GPU, which caused kernel warnings. Panthor didn't correctly handle the case where the partial mapping
    spanned multiple scatterlists and the mapping offset didn't point to the 1st page of starting scatterlist.
    The offset variable was not cleared after reaching the starting scatterlist. Following warning messages
    were seen. WARNING: CPU: 1 PID: 650 at drivers/iommu/io-pgtable-arm.c:659 __arm_lpae_unmap+0x254/0x5a0
    <snip> pc : __arm_lpae_unmap+0x254/0x5a0 lr : __arm_lpae_unmap+0x2cc/0x5a0 <snip> Call trace:
    __arm_lpae_unmap+0x254/0x5a0 __arm_lpae_unmap+0x108/0x5a0 __arm_lpae_unmap+0x108/0x5a0
    __arm_lpae_unmap+0x108/0x5a0 arm_lpae_unmap_pages+0x80/0xa0 panthor_vm_unmap_pages+0xac/0x1c8 [panthor]
    panthor_gpuva_sm_step_unmap+0x4c/0xc8 [panthor] op_unmap_cb.isra.23.constprop.30+0x54/0x80
    __drm_gpuvm_sm_unmap+0x184/0x1c8 drm_gpuvm_sm_unmap+0x40/0x60 panthor_vm_exec_op+0xa8/0x120 [panthor]
    panthor_vm_bind_exec_sync_op+0xc4/0xe8 [panthor] panthor_ioctl_vm_bind+0x10c/0x170 [panthor]
    drm_ioctl_kernel+0xbc/0x138 drm_ioctl+0x210/0x4b0 __arm64_sys_ioctl+0xb0/0xf8 invoke_syscall+0x4c/0x110
    el0_svc_common.constprop.1+0x98/0xf8 do_el0_svc+0x24/0x38 el0_svc+0x34/0xc8 el0t_64_sync_handler+0xa0/0xc8
    el0t_64_sync+0x174/0x178 <snip> panthor : [drm] drm_WARN_ON(unmapped_sz != pgsize * pgcount) WARNING: CPU:
    1 PID: 650 at drivers/gpu/drm/panthor/panthor_mmu.c:922 panthor_vm_unmap_pages+0x124/0x1c8 [panthor]
    <snip> pc : panthor_vm_unmap_pages+0x124/0x1c8 [panthor] lr : panthor_vm_unmap_pages+0x124/0x1c8 [panthor]
    <snip> panthor : [drm] *ERROR* failed to unmap range ffffa388f000-ffffa3890000 (requested range
    ffffa388c000-ffffa3890000) (CVE-2024-53116)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53116");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
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
        "os_version": "24.04"
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
