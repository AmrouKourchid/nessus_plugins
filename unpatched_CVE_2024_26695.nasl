#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228188);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26695");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26695");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: crypto: ccp - Fix null pointer
    dereference in __sev_platform_shutdown_locked The SEV platform device can be shutdown with a null
    psp_master, e.g., using DEBUG_TEST_DRIVER_REMOVE. Found using KASAN: [ 137.148210] ccp 0000:23:00.1:
    enabling device (0000 -> 0002) [ 137.162647] ccp 0000:23:00.1: no command queues available [ 137.170598]
    ccp 0000:23:00.1: sev enabled [ 137.174645] ccp 0000:23:00.1: psp enabled [ 137.178890] general protection
    fault, probably for non-canonical address 0xdffffc000000001e: 0000 [#1] PREEMPT SMP DEBUG_PAGEALLOC KASAN
    NOPTI [ 137.182693] KASAN: null-ptr-deref in range [0x00000000000000f0-0x00000000000000f7] [ 137.182693]
    CPU: 93 PID: 1 Comm: swapper/0 Not tainted 6.8.0-rc1+ #311 [ 137.182693] RIP:
    0010:__sev_platform_shutdown_locked+0x51/0x180 [ 137.182693] Code: 08 80 3c 08 00 0f 85 0e 01 00 00 48 8b
    1d 67 b6 01 08 48 b8 00 00 00 00 00 fc ff df 48 8d bb f0 00 00 00 48 89 f9 48 c1 e9 03 <80> 3c 01 00 0f 85
    fe 00 00 00 48 8b 9b f0 00 00 00 48 85 db 74 2c [ 137.182693] RSP: 0018:ffffc900000cf9b0 EFLAGS: 00010216
    [ 137.182693] RAX: dffffc0000000000 RBX: 0000000000000000 RCX: 000000000000001e [ 137.182693] RDX:
    0000000000000000 RSI: 0000000000000008 RDI: 00000000000000f0 [ 137.182693] RBP: ffffc900000cf9c8 R08:
    0000000000000000 R09: fffffbfff58f5a66 [ 137.182693] R10: ffffc900000cf9c8 R11: ffffffffac7ad32f R12:
    ffff8881e5052c28 [ 137.182693] R13: ffff8881e5052c28 R14: ffff8881758e43e8 R15: ffffffffac64abf8 [
    137.182693] FS: 0000000000000000(0000) GS:ffff889de7000000(0000) knlGS:0000000000000000 [ 137.182693] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 137.182693] CR2: 0000000000000000 CR3: 0000001cf7c7e000
    CR4: 0000000000350ef0 [ 137.182693] Call Trace: [ 137.182693] <TASK> [ 137.182693] ? show_regs+0x6c/0x80 [
    137.182693] ? __die_body+0x24/0x70 [ 137.182693] ? die_addr+0x4b/0x80 [ 137.182693] ?
    exc_general_protection+0x126/0x230 [ 137.182693] ? asm_exc_general_protection+0x2b/0x30 [ 137.182693] ?
    __sev_platform_shutdown_locked+0x51/0x180 [ 137.182693] sev_firmware_shutdown.isra.0+0x1e/0x80 [
    137.182693] sev_dev_destroy+0x49/0x100 [ 137.182693] psp_dev_destroy+0x47/0xb0 [ 137.182693]
    sp_destroy+0xbb/0x240 [ 137.182693] sp_pci_remove+0x45/0x60 [ 137.182693] pci_device_remove+0xaa/0x1d0 [
    137.182693] device_remove+0xc7/0x170 [ 137.182693] really_probe+0x374/0xbe0 [ 137.182693] ?
    srso_return_thunk+0x5/0x5f [ 137.182693] __driver_probe_device+0x199/0x460 [ 137.182693]
    driver_probe_device+0x4e/0xd0 [ 137.182693] __driver_attach+0x191/0x3d0 [ 137.182693] ?
    __pfx___driver_attach+0x10/0x10 [ 137.182693] bus_for_each_dev+0x100/0x190 [ 137.182693] ?
    __pfx_bus_for_each_dev+0x10/0x10 [ 137.182693] ? __kasan_check_read+0x15/0x20 [ 137.182693] ?
    srso_return_thunk+0x5/0x5f [ 137.182693] ? _raw_spin_unlock+0x27/0x50 [ 137.182693]
    driver_attach+0x41/0x60 [ 137.182693] bus_add_driver+0x2a8/0x580 [ 137.182693] driver_register+0x141/0x480
    [ 137.182693] __pci_register_driver+0x1d6/0x2a0 [ 137.182693] ? srso_return_thunk+0x5/0x5f [ 137.182693] ?
    esrt_sysfs_init+0x1cd/0x5d0 [ 137.182693] ? __pfx_sp_mod_init+0x10/0x10 [ 137.182693]
    sp_pci_init+0x22/0x30 [ 137.182693] sp_mod_init+0x14/0x30 [ 137.182693] ? __pfx_sp_mod_init+0x10/0x10 [
    137.182693] do_one_initcall+0xd1/0x470 [ 137.182693] ? __pfx_do_one_initcall+0x10/0x10 [ 137.182693] ?
    parameq+0x80/0xf0 [ 137.182693] ? srso_return_thunk+0x5/0x5f [ 137.182693] ? __kmalloc+0x3b0/0x4e0 [
    137.182693] ? kernel_init_freeable+0x92d/0x1050 [ 137.182693] ? kasan_populate_vmalloc_pte+0x171/0x190 [
    137.182693] ? srso_return_thunk+0x5/0x5f [ 137.182693] kernel_init_freeable+0xa64/0x1050 [ 137.182693] ?
    __pfx_kernel_init+0x10/0x10 [ 137.182693] kernel_init+0x24/0x160 [ 137.182693] ? __switch_to_asm+0x3e/0x70
    [ 137.182693] ret_from_fork+0x40/0x80 [ 137.182693] ? __pfx_kernel_init+0x1 ---truncated---
    (CVE-2024-26695)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
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
