#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229747);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47576");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47576");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: scsi_debug: Sanity check block
    descriptor length in resp_mode_select() In resp_mode_select() sanity check the block descriptor len to
    avoid UAF. BUG: KASAN: use-after-free in resp_mode_select+0xa4c/0xb40 drivers/scsi/scsi_debug.c:2509 Read
    of size 1 at addr ffff888026670f50 by task scsicmd/15032 CPU: 1 PID: 15032 Comm: scsicmd Not tainted
    5.15.0-01d0625 #15 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Call Trace: <TASK>
    dump_stack_lvl+0x89/0xb5 lib/dump_stack.c:107 print_address_description.constprop.9+0x28/0x160
    mm/kasan/report.c:257 kasan_report.cold.14+0x7d/0x117 mm/kasan/report.c:443
    __asan_report_load1_noabort+0x14/0x20 mm/kasan/report_generic.c:306 resp_mode_select+0xa4c/0xb40
    drivers/scsi/scsi_debug.c:2509 schedule_resp+0x4af/0x1a10 drivers/scsi/scsi_debug.c:5483
    scsi_debug_queuecommand+0x8c9/0x1e70 drivers/scsi/scsi_debug.c:7537 scsi_queue_rq+0x16b4/0x2d10
    drivers/scsi/scsi_lib.c:1521 blk_mq_dispatch_rq_list+0xb9b/0x2700 block/blk-mq.c:1640
    __blk_mq_sched_dispatch_requests+0x28f/0x590 block/blk-mq-sched.c:325
    blk_mq_sched_dispatch_requests+0x105/0x190 block/blk-mq-sched.c:358 __blk_mq_run_hw_queue+0xe5/0x150
    block/blk-mq.c:1762 __blk_mq_delay_run_hw_queue+0x4f8/0x5c0 block/blk-mq.c:1839
    blk_mq_run_hw_queue+0x18d/0x350 block/blk-mq.c:1891 blk_mq_sched_insert_request+0x3db/0x4e0 block/blk-mq-
    sched.c:474 blk_execute_rq_nowait+0x16b/0x1c0 block/blk-exec.c:63 sg_common_write.isra.18+0xeb3/0x2000
    drivers/scsi/sg.c:837 sg_new_write.isra.19+0x570/0x8c0 drivers/scsi/sg.c:775 sg_ioctl_common+0x14d6/0x2710
    drivers/scsi/sg.c:941 sg_ioctl+0xa2/0x180 drivers/scsi/sg.c:1166 __x64_sys_ioctl+0x19d/0x220 fs/ioctl.c:52
    do_syscall_64+0x3a/0x80 arch/x86/entry/common.c:50 entry_SYSCALL_64_after_hwframe+0x44/0xae
    arch/x86/entry/entry_64.S:113 (CVE-2021-47576)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47576");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
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
