#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229866);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47578");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47578");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: scsi_debug: Don't call kcalloc()
    if size arg is zero If the size arg to kcalloc() is zero, it returns ZERO_SIZE_PTR. Because of that, for a
    following NULL pointer check to work on the returned pointer, kcalloc() must not be called with the size
    arg equal to zero. Return early without error before the kcalloc() call if size arg is zero. BUG: KASAN:
    null-ptr-deref in memcpy include/linux/fortify-string.h:191 [inline] BUG: KASAN: null-ptr-deref in
    sg_copy_buffer+0x138/0x240 lib/scatterlist.c:974 Write of size 4 at addr 0000000000000010 by task syz-
    executor.1/22789 CPU: 1 PID: 22789 Comm: syz-executor.1 Not tainted 5.15.0-syzk #1 Hardware name: Red Hat
    KVM, BIOS 1.13.0-2 Call Trace: __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x89/0xb5
    lib/dump_stack.c:106 __kasan_report mm/kasan/report.c:446 [inline] kasan_report.cold.14+0x112/0x117
    mm/kasan/report.c:459 check_region_inline mm/kasan/generic.c:183 [inline] kasan_check_range+0x1a3/0x210
    mm/kasan/generic.c:189 memcpy+0x3b/0x60 mm/kasan/shadow.c:66 memcpy include/linux/fortify-string.h:191
    [inline] sg_copy_buffer+0x138/0x240 lib/scatterlist.c:974 do_dout_fetch drivers/scsi/scsi_debug.c:2954
    [inline] do_dout_fetch drivers/scsi/scsi_debug.c:2946 [inline] resp_verify+0x49e/0x930
    drivers/scsi/scsi_debug.c:4276 schedule_resp+0x4d8/0x1a70 drivers/scsi/scsi_debug.c:5478
    scsi_debug_queuecommand+0x8c9/0x1ec0 drivers/scsi/scsi_debug.c:7533 scsi_dispatch_cmd
    drivers/scsi/scsi_lib.c:1520 [inline] scsi_queue_rq+0x16b0/0x2d40 drivers/scsi/scsi_lib.c:1699
    blk_mq_dispatch_rq_list+0xb9b/0x2700 block/blk-mq.c:1639 __blk_mq_sched_dispatch_requests+0x28f/0x590
    block/blk-mq-sched.c:325 blk_mq_sched_dispatch_requests+0x105/0x190 block/blk-mq-sched.c:358
    __blk_mq_run_hw_queue+0xe5/0x150 block/blk-mq.c:1761 __blk_mq_delay_run_hw_queue+0x4f8/0x5c0 block/blk-
    mq.c:1838 blk_mq_run_hw_queue+0x18d/0x350 block/blk-mq.c:1891 blk_mq_sched_insert_request+0x3db/0x4e0
    block/blk-mq-sched.c:474 blk_execute_rq_nowait+0x16b/0x1c0 block/blk-exec.c:62 blk_execute_rq+0xdb/0x360
    block/blk-exec.c:102 sg_scsi_ioctl drivers/scsi/scsi_ioctl.c:621 [inline] scsi_ioctl+0x8bb/0x15c0
    drivers/scsi/scsi_ioctl.c:930 sg_ioctl_common+0x172d/0x2710 drivers/scsi/sg.c:1112 sg_ioctl+0xa2/0x180
    drivers/scsi/sg.c:1165 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:874 [inline]
    __se_sys_ioctl fs/ioctl.c:860 [inline] __x64_sys_ioctl+0x19d/0x220 fs/ioctl.c:860 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x3a/0x80 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2021-47578)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47578");

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
