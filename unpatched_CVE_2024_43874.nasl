#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229071);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-43874");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-43874");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: crypto: ccp - Fix null pointer
    dereference in __sev_snp_shutdown_locked Fix a null pointer dereference induced by
    DEBUG_TEST_DRIVER_REMOVE. Return from __sev_snp_shutdown_locked() if the psp_device or the sev_device
    structs are not initialized. Without the fix, the driver will produce the following splat: ccp
    0000:55:00.5: enabling device (0000 -> 0002) ccp 0000:55:00.5: sev enabled ccp 0000:55:00.5: psp enabled
    BUG: kernel NULL pointer dereference, address: 00000000000000f0 #PF: supervisor read access in kernel mode
    #PF: error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: 0000 [#1] PREEMPT SMP DEBUG_PAGEALLOC NOPTI
    CPU: 262 PID: 1 Comm: swapper/0 Not tainted 6.9.0-rc1+ #29 RIP: 0010:__sev_snp_shutdown_locked+0x2e/0x150
    Code: 00 55 48 89 e5 41 57 41 56 41 54 53 48 83 ec 10 41 89 f7 49 89 fe 65 48 8b 04 25 28 00 00 00 48 89
    45 d8 48 8b 05 6a 5a 7f 06 <4c> 8b a0 f0 00 00 00 41 0f b6 9c 24 a2 00 00 00 48 83 fb 02 0f 83 RSP:
    0018:ffffb2ea4014b7b8 EFLAGS: 00010286 RAX: 0000000000000000 RBX: ffff9e4acd2e0a28 RCX: 0000000000000000
    RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffb2ea4014b808 RBP: ffffb2ea4014b7e8 R08:
    0000000000000106 R09: 000000000003d9c0 R10: 0000000000000001 R11: ffffffffa39ff070 R12: ffff9e49d40590c8
    R13: 0000000000000000 R14: ffffb2ea4014b808 R15: 0000000000000000 FS: 0000000000000000(0000)
    GS:ffff9e58b1e00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00000000000000f0 CR3: 0000000418a3e001 CR4: 0000000000770ef0 PKRU: 55555554 Call Trace: <TASK> ?
    __die_body+0x6f/0xb0 ? __die+0xcc/0xf0 ? page_fault_oops+0x330/0x3a0 ? save_trace+0x2a5/0x360 ?
    do_user_addr_fault+0x583/0x630 ? exc_page_fault+0x81/0x120 ? asm_exc_page_fault+0x2b/0x30 ?
    __sev_snp_shutdown_locked+0x2e/0x150 __sev_firmware_shutdown+0x349/0x5b0 ? pm_runtime_barrier+0x66/0xe0
    sev_dev_destroy+0x34/0xb0 psp_dev_destroy+0x27/0x60 sp_destroy+0x39/0x90 sp_pci_remove+0x22/0x60
    pci_device_remove+0x4e/0x110 really_probe+0x271/0x4e0 __driver_probe_device+0x8f/0x160
    driver_probe_device+0x24/0x120 __driver_attach+0xc7/0x280 ? driver_attach+0x30/0x30
    bus_for_each_dev+0x10d/0x130 driver_attach+0x22/0x30 bus_add_driver+0x171/0x2b0 ?
    unaccepted_memory_init_kdump+0x20/0x20 driver_register+0x67/0x100 __pci_register_driver+0x83/0x90
    sp_pci_init+0x22/0x30 sp_mod_init+0x13/0x30 do_one_initcall+0xb8/0x290 ? sched_clock_noinstr+0xd/0x10 ?
    local_clock_noinstr+0x3e/0x100 ? stack_depot_save_flags+0x21e/0x6a0 ? local_clock+0x1c/0x60 ?
    stack_depot_save_flags+0x21e/0x6a0 ? sched_clock_noinstr+0xd/0x10 ? local_clock_noinstr+0x3e/0x100 ?
    __lock_acquire+0xd90/0xe30 ? sched_clock_noinstr+0xd/0x10 ? local_clock_noinstr+0x3e/0x100 ?
    __create_object+0x66/0x100 ? local_clock+0x1c/0x60 ? __create_object+0x66/0x100 ? parameq+0x1b/0x90 ?
    parse_one+0x6d/0x1d0 ? parse_args+0xd7/0x1f0 ? do_initcall_level+0x180/0x180 do_initcall_level+0xb0/0x180
    do_initcalls+0x60/0xa0 ? kernel_init+0x1f/0x1d0 do_basic_setup+0x41/0x50 kernel_init_freeable+0x1ac/0x230
    ? rest_init+0x1f0/0x1f0 kernel_init+0x1f/0x1d0 ? rest_init+0x1f0/0x1f0 ret_from_fork+0x3d/0x50 ?
    rest_init+0x1f0/0x1f0 ret_from_fork_asm+0x11/0x20 </TASK> Modules linked in: CR2: 00000000000000f0 ---[
    end trace 0000000000000000 ]--- RIP: 0010:__sev_snp_shutdown_locked+0x2e/0x150 Code: 00 55 48 89 e5 41 57
    41 56 41 54 53 48 83 ec 10 41 89 f7 49 89 fe 65 48 8b 04 25 28 00 00 00 48 89 45 d8 48 8b 05 6a 5a 7f 06
    <4c> 8b a0 f0 00 00 00 41 0f b6 9c 24 a2 00 00 00 48 83 fb 02 0f 83 RSP: 0018:ffffb2ea4014b7b8 EFLAGS:
    00010286 RAX: 0000000000000000 RBX: ffff9e4acd2e0a28 RCX: 0000000000000000 RDX: 0000000 ---truncated---
    (CVE-2024-43874)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43874");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
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
