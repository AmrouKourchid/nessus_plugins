#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230158);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47393");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47393");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: hwmon: (mlxreg-fan) Return non-zero
    value when fan current state is enforced from sysfs Fan speed minimum can be enforced from sysfs. For
    example, setting current fan speed to 20 is used to enforce fan speed to be at 100% speed, 19 - to be not
    below 90% speed, etcetera. This feature provides ability to limit fan speed according to some system wise
    considerations, like absence of some replaceable units or high system ambient temperature. Request for
    changing fan minimum speed is configuration request and can be set only through 'sysfs' write procedure.
    In this situation value of argument 'state' is above nominal fan speed maximum. Return non-zero code in
    this case to avoid thermal_cooling_device_stats_update() call, because in this case statistics update
    violates thermal statistics table range. The issues is observed in case kernel is configured with option
    CONFIG_THERMAL_STATISTICS. Here is the trace from KASAN: [ 159.506659] BUG: KASAN: slab-out-of-bounds in
    thermal_cooling_device_stats_update+0x7d/0xb0 [ 159.516016] Read of size 4 at addr ffff888116163840 by
    task hw-management.s/7444 [ 159.545625] Call Trace: [ 159.548366] dump_stack+0x92/0xc1 [ 159.552084] ?
    thermal_cooling_device_stats_update+0x7d/0xb0 [ 159.635869] thermal_zone_device_update+0x345/0x780 [
    159.688711] thermal_zone_device_set_mode+0x7d/0xc0 [ 159.694174] mlxsw_thermal_modules_init+0x48f/0x590
    [mlxsw_core] [ 159.700972] ? mlxsw_thermal_set_cur_state+0x5a0/0x5a0 [mlxsw_core] [ 159.731827]
    mlxsw_thermal_init+0x763/0x880 [mlxsw_core] [ 160.070233] RIP: 0033:0x7fd995909970 [ 160.074239] Code: 73
    01 c3 48 8b 0d 28 d5 2b 00 f7 d8 64 89 01 48 83 c8 ff c3 66 0f 1f 44 00 00 83 3d 99 2d 2c 00 00 75 10 b8
    01 00 00 00 0f 05 <48> 3d 01 f0 ff .. [ 160.095242] RSP: 002b:00007fff54f5d938 EFLAGS: 00000246 ORIG_RAX:
    0000000000000001 [ 160.103722] RAX: ffffffffffffffda RBX: 0000000000000013 RCX: 00007fd995909970 [
    160.111710] RDX: 0000000000000013 RSI: 0000000001906008 RDI: 0000000000000001 [ 160.119699] RBP:
    0000000001906008 R08: 00007fd995bc9760 R09: 00007fd996210700 [ 160.127687] R10: 0000000000000073 R11:
    0000000000000246 R12: 0000000000000013 [ 160.135673] R13: 0000000000000001 R14: 00007fd995bc8600 R15:
    0000000000000013 [ 160.143671] [ 160.145338] Allocated by task 2924: [ 160.149242]
    kasan_save_stack+0x19/0x40 [ 160.153541] __kasan_kmalloc+0x7f/0xa0 [ 160.157743] __kmalloc+0x1a2/0x2b0 [
    160.161552] thermal_cooling_device_setup_sysfs+0xf9/0x1a0 [ 160.167687]
    __thermal_cooling_device_register+0x1b5/0x500 [ 160.173833]
    devm_thermal_of_cooling_device_register+0x60/0xa0 [ 160.180356] mlxreg_fan_probe+0x474/0x5e0 [mlxreg_fan]
    [ 160.248140] [ 160.249807] The buggy address belongs to the object at ffff888116163400 [ 160.249807]
    which belongs to the cache kmalloc-1k of size 1024 [ 160.263814] The buggy address is located 64 bytes to
    the right of [ 160.263814] 1024-byte region [ffff888116163400, ffff888116163800) [ 160.277536] The buggy
    address belongs to the page: [ 160.282898] page:0000000012275840 refcount:1 mapcount:0
    mapping:0000000000000000 index:0xffff888116167000 pfn:0x116160 [ 160.294872] head:0000000012275840 order:3
    compound_mapcount:0 compound_pincount:0 [ 160.303251] flags: 0x200000000010200(slab|head|node=0|zone=2) [
    160.309694] raw: 0200000000010200 ffffea00046f7208 ffffea0004928208 ffff88810004dbc0 [ 160.318367] raw:
    ffff888116167000 00000000000a0006 00000001ffffffff 0000000000000000 [ 160.327033] page dumped because:
    kasan: bad access detected [ 160.333270] [ 160.334937] Memory state around the buggy address: [
    160.356469] >ffff888116163800: fc .. (CVE-2021-47393)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
