#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224312);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47497");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47497");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: nvmem: Fix shift-out-of-bound (UBSAN)
    with byte size cells If a cell has 'nbits' equal to a multiple of BITS_PER_BYTE the logic *p &=
    GENMASK((cell->nbits%BITS_PER_BYTE) - 1, 0); will become undefined behavior because nbits modulo
    BITS_PER_BYTE is 0, and we subtract one from that making a large number that is then shifted more than the
    number of bits that fit into an unsigned long. UBSAN reports this problem: UBSAN: shift-out-of-bounds in
    drivers/nvmem/core.c:1386:8 shift exponent 64 is too large for 64-bit type 'unsigned long' CPU: 6 PID: 7
    Comm: kworker/u16:0 Not tainted 5.15.0-rc3+ #9 Hardware name: Google Lazor (rev3+) with KB Backlight (DT)
    Workqueue: events_unbound deferred_probe_work_func Call trace: dump_backtrace+0x0/0x170
    show_stack+0x24/0x30 dump_stack_lvl+0x64/0x7c dump_stack+0x18/0x38 ubsan_epilogue+0x10/0x54
    __ubsan_handle_shift_out_of_bounds+0x180/0x194 __nvmem_cell_read+0x1ec/0x21c nvmem_cell_read+0x58/0x94
    nvmem_cell_read_variable_common+0x4c/0xb0 nvmem_cell_read_variable_le_u32+0x40/0x100
    a6xx_gpu_init+0x170/0x2f4 adreno_bind+0x174/0x284 component_bind_all+0xf0/0x264 msm_drm_bind+0x1d8/0x7a0
    try_to_bring_up_master+0x164/0x1ac __component_add+0xbc/0x13c component_add+0x20/0x2c
    dp_display_probe+0x340/0x384 platform_probe+0xc0/0x100 really_probe+0x110/0x304
    __driver_probe_device+0xb8/0x120 driver_probe_device+0x4c/0xfc __device_attach_driver+0xb0/0x128
    bus_for_each_drv+0x90/0xdc __device_attach+0xc8/0x174 device_initial_probe+0x20/0x2c
    bus_probe_device+0x40/0xa4 deferred_probe_work_func+0x7c/0xb8 process_one_work+0x128/0x21c
    process_scheduled_works+0x40/0x54 worker_thread+0x1ec/0x2a8 kthread+0x138/0x158 ret_from_fork+0x10/0x20
    Fix it by making sure there are any bits to mask out. (CVE-2021-47497)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47497");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
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
