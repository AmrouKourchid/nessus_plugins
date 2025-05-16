#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225252);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48969");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48969");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: xen-netfront: Fix NULL sring after
    live migration A NAPI is setup for each network sring to poll data to kernel The sring with source host is
    destroyed before live migration and new sring with target host is setup after live migration. The NAPI for
    the old sring is not deleted until setup new sring with target host after migration. With
    busy_poll/busy_read enabled, the NAPI can be polled before got deleted when resume VM. BUG: unable to
    handle kernel NULL pointer dereference at 0000000000000008 IP: xennet_poll+0xae/0xd20 PGD 0 P4D 0 Oops:
    0000 [#1] SMP PTI Call Trace: finish_task_switch+0x71/0x230 timerqueue_del+0x1d/0x40
    hrtimer_try_to_cancel+0xb5/0x110 xennet_alloc_rx_buffers+0x2a0/0x2a0 napi_busy_loop+0xdb/0x270
    sock_poll+0x87/0x90 do_sys_poll+0x26f/0x580 tracing_map_insert+0x1d4/0x2f0 event_hist_trigger+0x14a/0x260
    finish_task_switch+0x71/0x230 __schedule+0x256/0x890 recalc_sigpending+0x1b/0x50 xen_sched_clock+0x15/0x20
    __rb_reserve_next+0x12d/0x140 ring_buffer_lock_reserve+0x123/0x3d0 event_triggers_call+0x87/0xb0
    trace_event_buffer_commit+0x1c4/0x210 xen_clocksource_get_cycles+0x15/0x20 ktime_get_ts64+0x51/0xf0
    SyS_ppoll+0x160/0x1a0 SyS_ppoll+0x160/0x1a0 do_syscall_64+0x73/0x130
    entry_SYSCALL_64_after_hwframe+0x41/0xa6 ... RIP: xennet_poll+0xae/0xd20 RSP: ffffb4f041933900 CR2:
    0000000000000008 ---[ end trace f8601785b354351c ]--- xen frontend should remove the NAPIs for the old
    srings before live migration as the bond srings are destroyed There is a tiny window between the srings
    are set to NULL and the NAPIs are disabled, It is safe as the NAPI threads are still frozen at that time
    (CVE-2022-48969)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48969");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
