#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226948);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52866");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52866");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: HID: uclogic: Fix user-memory-access
    bug in uclogic_params_ugee_v2_init_event_hooks() When CONFIG_HID_UCLOGIC=y and CONFIG_KUNIT_ALL_TESTS=y,
    launch kernel and then the below user-memory-access bug occurs. In
    hid_test_uclogic_params_cleanup_event_hooks(),it call uclogic_params_ugee_v2_init_event_hooks() with the
    first arg=NULL, so when it calls uclogic_params_ugee_v2_has_battery(), the hid_get_drvdata() will access
    hdev->dev with hdev=NULL, which will cause below user-memory-access. So add a fake_device with quirks
    member and call hid_set_drvdata() to assign hdev->dev->driver_data which avoids the null-ptr-def bug for
    drvdata->quirks in uclogic_params_ugee_v2_has_battery(). After applying this patch, the below user-memory-
    access bug never occurs. general protection fault, probably for non-canonical address 0xdffffc0000000329:
    0000 [#1] PREEMPT SMP KASAN KASAN: probably user-memory-access in range
    [0x0000000000001948-0x000000000000194f] CPU: 5 PID: 2189 Comm: kunit_try_catch Tainted: G B W N 6.6.0-rc2+
    #30 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 RIP:
    0010:uclogic_params_ugee_v2_init_event_hooks+0x87/0x600 Code: f3 f3 65 48 8b 14 25 28 00 00 00 48 89 54 24
    60 31 d2 48 89 fa c7 44 24 30 00 00 00 00 48 c7 44 24 28 02 f8 02 01 48 c1 ea 03 <80> 3c 02 00 0f 85 2c 04
    00 00 48 8b 9d 48 19 00 00 48 b8 00 00 00 RSP: 0000:ffff88810679fc88 EFLAGS: 00010202 RAX:
    dffffc0000000000 RBX: 0000000000000004 RCX: 0000000000000000 RDX: 0000000000000329 RSI: ffff88810679fd88
    RDI: 0000000000001948 RBP: 0000000000000000 R08: 0000000000000000 R09: ffffed1020f639f0 R10:
    ffff888107b1cf87 R11: 0000000000000400 R12: 1ffff11020cf3f92 R13: ffff88810679fd88 R14: ffff888100b97b08
    R15: ffff8881030bb080 FS: 0000000000000000(0000) GS:ffff888119e80000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000000000000 CR3: 0000000005286001 CR4: 0000000000770ee0
    DR0: ffffffff8fdd6cf4 DR1: ffffffff8fdd6cf5 DR2: ffffffff8fdd6cf6 DR3: ffffffff8fdd6cf7 DR6:
    00000000fffe0ff0 DR7: 0000000000000600 PKRU: 55555554 Call Trace: <TASK> ? die_addr+0x3d/0xa0 ?
    exc_general_protection+0x144/0x220 ? asm_exc_general_protection+0x22/0x30 ?
    uclogic_params_ugee_v2_init_event_hooks+0x87/0x600 ? sched_clock_cpu+0x69/0x550 ?
    uclogic_parse_ugee_v2_desc_gen_params+0x70/0x70 ? load_balance+0x2950/0x2950 ?
    rcu_trc_cmpxchg_need_qs+0x67/0xa0 hid_test_uclogic_params_cleanup_event_hooks+0x9e/0x1a0 ?
    uclogic_params_ugee_v2_init_event_hooks+0x600/0x600 ? __switch_to+0x5cf/0xe60 ? migrate_enable+0x260/0x260
    ? __kthread_parkme+0x83/0x150 ? kunit_try_run_case_cleanup+0xe0/0xe0
    kunit_generic_run_threadfn_adapter+0x4a/0x90 ? kunit_try_catch_throw+0x80/0x80 kthread+0x2b5/0x380 ?
    kthread_complete_and_exit+0x20/0x20 ret_from_fork+0x2d/0x70 ? kthread_complete_and_exit+0x20/0x20
    ret_from_fork_asm+0x11/0x20 </TASK> Modules linked in: Dumping ftrace buffer: (ftrace buffer empty) ---[
    end trace 0000000000000000 ]--- RIP: 0010:uclogic_params_ugee_v2_init_event_hooks+0x87/0x600 Code: f3 f3
    65 48 8b 14 25 28 00 00 00 48 89 54 24 60 31 d2 48 89 fa c7 44 24 30 00 00 00 00 48 c7 44 24 28 02 f8 02
    01 48 c1 ea 03 <80> 3c 02 00 0f 85 2c 04 00 00 48 8b 9d 48 19 00 00 48 b8 00 00 00 RSP:
    0000:ffff88810679fc88 EFLAGS: 00010202 RAX: dffffc0000000000 RBX: 0000000000000004 RCX: 0000000000000000
    RDX: 0000000000000329 RSI: ffff88810679fd88 RDI: 0000000000001948 RBP: 0000000000000000 R08:
    0000000000000000 R09: ffffed1020f639f0 R10: ffff888107b1cf87 R11: 0000000000000400 R12: 1ffff11020cf3f92
    R13: ffff88810679fd88 R14: ffff888100b97b08 R15: ffff8881030bb080 FS: 0000000000000000(0000)
    GS:ffff888119e80000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    0000000000000000 CR3: 0000000005286001 CR4: 0000000000770ee0 DR0: ffffffff8fdd6cf4 DR1: ---truncated---
    (CVE-2023-52866)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52866");

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
