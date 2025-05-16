#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224417);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47346");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47346");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: coresight: tmc-etf: Fix global-out-of-
    bounds in tmc_update_etf_buffer() commit 6f755e85c332 (coresight: Add helper for inserting
    synchronization packets) removed trailing '\0' from barrier_pkt array and updated the call sites like
    etb_update_buffer() to have proper checks for barrier_pkt size before read but missed updating
    tmc_update_etf_buffer() which still reads barrier_pkt past the array size resulting in KASAN out-of-bounds
    bug. Fix this by adding a check for barrier_pkt size before accessing like it is done in
    etb_update_buffer(). BUG: KASAN: global-out-of-bounds in tmc_update_etf_buffer+0x4b8/0x698 Read of size 4
    at addr ffffffd05b7d1030 by task perf/2629 Call trace: dump_backtrace+0x0/0x27c show_stack+0x20/0x2c
    dump_stack+0x11c/0x188 print_address_description+0x3c/0x4a4 __kasan_report+0x140/0x164
    kasan_report+0x10/0x18 __asan_report_load4_noabort+0x1c/0x24 tmc_update_etf_buffer+0x4b8/0x698
    etm_event_stop+0x248/0x2d8 etm_event_del+0x20/0x2c event_sched_out+0x214/0x6f0 group_sched_out+0xd0/0x270
    ctx_sched_out+0x2ec/0x518 __perf_event_task_sched_out+0x4fc/0xe6c __schedule+0x1094/0x16a0
    preempt_schedule_irq+0x88/0x170 arm64_preempt_schedule_irq+0xf0/0x18c el1_irq+0xe8/0x180
    perf_event_exec+0x4d8/0x56c setup_new_exec+0x204/0x400 load_elf_binary+0x72c/0x18c0
    search_binary_handler+0x13c/0x420 load_script+0x500/0x6c4 search_binary_handler+0x13c/0x420
    exec_binprm+0x118/0x654 __do_execve_file+0x77c/0xba4 __arm64_compat_sys_execve+0x98/0xac
    el0_svc_common+0x1f8/0x5e0 el0_svc_compat_handler+0x84/0xb0 el0_svc_compat+0x10/0x50 The buggy address
    belongs to the variable: barrier_pkt+0x10/0x40 Memory state around the buggy address: ffffffd05b7d0f00: fa
    fa fa fa 04 fa fa fa fa fa fa fa 00 00 00 00 ffffffd05b7d0f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 >ffffffd05b7d1000: 00 00 00 00 00 00 fa fa fa fa fa fa 00 00 00 03 ^ ffffffd05b7d1080: fa fa fa fa
    00 02 fa fa fa fa fa fa 03 fa fa fa ffffffd05b7d1100: fa fa fa fa 00 00 00 00 05 fa fa fa fa fa fa fa
    ================================================================== (CVE-2021-47346)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47346");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
