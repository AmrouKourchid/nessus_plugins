#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224402);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47097");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47097");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Input: elantech - fix stack out of
    bound access in elantech_change_report_id() The array param[] in elantech_change_report_id() must be at
    least 3 bytes, because elantech_read_reg_params() is calling ps2_command() with PSMOUSE_CMD_GETINFO, that
    is going to access 3 bytes from param[], but it's defined in the stack as an array of 2 bytes, therefore
    we have a potential stack out-of-bounds access here, also confirmed by KASAN: [ 6.512374] BUG: KASAN:
    stack-out-of-bounds in __ps2_command+0x372/0x7e0 [ 6.512397] Read of size 1 at addr ffff8881024d77c2 by
    task kworker/2:1/118 [ 6.512416] CPU: 2 PID: 118 Comm: kworker/2:1 Not tainted 5.13.0-22-generic
    #22+arighi20211110 [ 6.512428] Hardware name: LENOVO 20T8000QGE/20T8000QGE, BIOS R1AET32W (1.08 )
    08/14/2020 [ 6.512436] Workqueue: events_long serio_handle_event [ 6.512453] Call Trace: [ 6.512462]
    show_stack+0x52/0x58 [ 6.512474] dump_stack+0xa1/0xd3 [ 6.512487]
    print_address_description.constprop.0+0x1d/0x140 [ 6.512502] ? __ps2_command+0x372/0x7e0 [ 6.512516]
    __kasan_report.cold+0x7d/0x112 [ 6.512527] ? _raw_write_lock_irq+0x20/0xd0 [ 6.512539] ?
    __ps2_command+0x372/0x7e0 [ 6.512552] kasan_report+0x3c/0x50 [ 6.512564] __asan_load1+0x6a/0x70 [
    6.512575] __ps2_command+0x372/0x7e0 [ 6.512589] ? ps2_drain+0x240/0x240 [ 6.512601] ?
    dev_printk_emit+0xa2/0xd3 [ 6.512612] ? dev_vprintk_emit+0xc5/0xc5 [ 6.512621] ?
    __kasan_check_write+0x14/0x20 [ 6.512634] ? mutex_lock+0x8f/0xe0 [ 6.512643] ?
    __mutex_lock_slowpath+0x20/0x20 [ 6.512655] ps2_command+0x52/0x90 [ 6.512670]
    elantech_ps2_command+0x4f/0xc0 [psmouse] [ 6.512734] elantech_change_report_id+0x1e6/0x256 [psmouse] [
    6.512799] ? elantech_report_trackpoint.constprop.0.cold+0xd/0xd [psmouse] [ 6.512863] ?
    ps2_command+0x7f/0x90 [ 6.512877] elantech_query_info.cold+0x6bd/0x9ed [psmouse] [ 6.512943] ?
    elantech_setup_ps2+0x460/0x460 [psmouse] [ 6.513005] ? psmouse_reset+0x69/0xb0 [psmouse] [ 6.513064] ?
    psmouse_attr_set_helper+0x2a0/0x2a0 [psmouse] [ 6.513122] ? phys_pmd_init+0x30e/0x521 [ 6.513137]
    elantech_init+0x8a/0x200 [psmouse] [ 6.513200] ? elantech_init_ps2+0xf0/0xf0 [psmouse] [ 6.513249] ?
    elantech_query_info+0x440/0x440 [psmouse] [ 6.513296] ? synaptics_send_cmd+0x60/0x60 [psmouse] [ 6.513342]
    ? elantech_query_info+0x440/0x440 [psmouse] [ 6.513388] ? psmouse_try_protocol+0x11e/0x170 [psmouse] [
    6.513432] psmouse_extensions+0x65d/0x6e0 [psmouse] [ 6.513476] ? psmouse_try_protocol+0x170/0x170
    [psmouse] [ 6.513519] ? mutex_unlock+0x22/0x40 [ 6.513526] ? ps2_command+0x7f/0x90 [ 6.513536] ?
    psmouse_probe+0xa3/0xf0 [psmouse] [ 6.513580] psmouse_switch_protocol+0x27d/0x2e0 [psmouse] [ 6.513624]
    psmouse_connect+0x272/0x530 [psmouse] [ 6.513669] serio_driver_probe+0x55/0x70 [ 6.513679]
    really_probe+0x190/0x720 [ 6.513689] driver_probe_device+0x160/0x1f0 [ 6.513697]
    device_driver_attach+0x119/0x130 [ 6.513705] ? device_driver_attach+0x130/0x130 [ 6.513713]
    __driver_attach+0xe7/0x1a0 [ 6.513720] ? device_driver_attach+0x130/0x130 [ 6.513728]
    bus_for_each_dev+0xfb/0x150 [ 6.513738] ? subsys_dev_iter_exit+0x10/0x10 [ 6.513748] ?
    _raw_write_unlock_bh+0x30/0x30 [ 6.513757] driver_attach+0x2d/0x40 [ 6.513764]
    serio_handle_event+0x199/0x3d0 [ 6.513775] process_one_work+0x471/0x740 [ 6.513785]
    worker_thread+0x2d2/0x790 [ 6.513794] ? process_one_work+0x740/0x740 [ 6.513802] kthread+0x1b4/0x1e0 [
    6.513809] ? set_kthread_struct+0x80/0x80 [ 6.513816] ret_from_fork+0x22/0x30 [ 6.513832] The buggy address
    belongs to the page: [ 6.513838] page:00000000bc35e189 refcount:0 mapcount:0 mapping:0000000000000000
    index:0x0 pfn:0x1024d7 [ 6.513847] flags: 0x17ffffc0000000(node=0|zone=2|lastcpupid=0x1fffff) [ 6.513860]
    raw: 0 ---truncated--- (CVE-2021-47097)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47097");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
