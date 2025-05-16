#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224297);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47441");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47441");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mlxsw: thermal: Fix out-of-bounds
    memory accesses Currently, mlxsw allows cooling states to be set above the maximum cooling state supported
    by the driver: # cat /sys/class/thermal/thermal_zone2/cdev0/type mlxsw_fan # cat
    /sys/class/thermal/thermal_zone2/cdev0/max_state 10 # echo 18 >
    /sys/class/thermal/thermal_zone2/cdev0/cur_state # echo $? 0 This results in out-of-bounds memory accesses
    when thermal state transition statistics are enabled (CONFIG_THERMAL_STATISTICS=y), as the transition
    table is accessed with a too large index (state) [1]. According to the thermal maintainer, it is the
    responsibility of the driver to reject such operations [2]. Therefore, return an error when the state to
    be set exceeds the maximum cooling state supported by the driver. To avoid dead code, as suggested by the
    thermal maintainer [3], partially revert commit a421ce088ac8 (mlxsw: core: Extend cooling device with
    cooling levels) that tried to interpret these invalid cooling states (above the maximum) in a special
    way. The cooling levels array is not removed in order to prevent the fans going below 20% PWM, which would
    cause them to get stuck at 0% PWM. [1] BUG: KASAN: slab-out-of-bounds in
    thermal_cooling_device_stats_update+0x271/0x290 Read of size 4 at addr ffff8881052f7bf8 by task
    kworker/0:0/5 CPU: 0 PID: 5 Comm: kworker/0:0 Not tainted 5.15.0-rc3-custom-45935-gce1adf704b14 #122
    Hardware name: Mellanox Technologies Ltd. MSN2410-CB2FO/SA000874, BIOS 4.6.5 03/08/2016 Workqueue:
    events_freezable_power_ thermal_zone_device_check Call Trace: dump_stack_lvl+0x8b/0xb3
    print_address_description.constprop.0+0x1f/0x140 kasan_report.cold+0x7f/0x11b
    thermal_cooling_device_stats_update+0x271/0x290 __thermal_cdev_update+0x15e/0x4e0
    thermal_cdev_update+0x9f/0xe0 step_wise_throttle+0x770/0xee0 thermal_zone_device_update+0x3f6/0xdf0
    process_one_work+0xa42/0x1770 worker_thread+0x62f/0x13e0 kthread+0x3ee/0x4e0 ret_from_fork+0x1f/0x30
    Allocated by task 1: kasan_save_stack+0x1b/0x40 __kasan_kmalloc+0x7c/0x90
    thermal_cooling_device_setup_sysfs+0x153/0x2c0 __thermal_cooling_device_register.part.0+0x25b/0x9c0
    thermal_cooling_device_register+0xb3/0x100 mlxsw_thermal_init+0x5c5/0x7e0
    __mlxsw_core_bus_device_register+0xcb3/0x19c0 mlxsw_core_bus_device_register+0x56/0xb0
    mlxsw_pci_probe+0x54f/0x710 local_pci_probe+0xc6/0x170 pci_device_probe+0x2b2/0x4d0
    really_probe+0x293/0xd10 __driver_probe_device+0x2af/0x440 driver_probe_device+0x51/0x1e0
    __driver_attach+0x21b/0x530 bus_for_each_dev+0x14c/0x1d0 bus_add_driver+0x3ac/0x650
    driver_register+0x241/0x3d0 mlxsw_sp_module_init+0xa2/0x174 do_one_initcall+0xee/0x5f0
    kernel_init_freeable+0x45a/0x4de kernel_init+0x1f/0x210 ret_from_fork+0x1f/0x30 The buggy address belongs
    to the object at ffff8881052f7800 which belongs to the cache kmalloc-1k of size 1024 The buggy address is
    located 1016 bytes inside of 1024-byte region [ffff8881052f7800, ffff8881052f7c00) The buggy address
    belongs to the page: page:0000000052355272 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0
    pfn:0x1052f0 head:0000000052355272 order:3 compound_mapcount:0 compound_pincount:0 flags:
    0x200000000010200(slab|head|node=0|zone=2) raw: 0200000000010200 ffffea0005034800 0000000300000003
    ffff888100041dc0 raw: 0000000000000000 0000000000100010 00000001ffffffff 0000000000000000 page dumped
    because: kasan: bad access detected Memory state around the buggy address: ffff8881052f7a80: 00 00 00 00
    00 00 04 fc fc fc fc fc fc fc fc fc ffff8881052f7b00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
    >ffff8881052f7b80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc ^ ffff8881052f7c00: fc fc fc fc fc fc
    fc fc fc fc fc fc fc fc fc fc ffff8881052f7c80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc [2]
    https://lore.kernel.org/linux-pm/9aca37cb-1629-5c67- ---truncated--- (CVE-2021-47441)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47441");

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
    "name": "kernel",
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
