#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225671);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48978");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48978");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: HID: core: fix shift-out-of-bounds in
    hid_report_raw_event Syzbot reported shift-out-of-bounds in hid_report_raw_event. microsoft
    0003:045E:07DA.0001: hid_field_extract() called with n (128) > 32! (swapper/0)
    ====================================================================== UBSAN: shift-out-of-bounds in
    drivers/hid/hid-core.c:1323:20 shift exponent 127 is too large for 32-bit type 'int' CPU: 0 PID: 0 Comm:
    swapper/0 Not tainted 6.1.0-rc4-syzkaller-00159-g4bbf3422df78 #0 Hardware name: Google Compute
    Engine/Google Compute Engine, BIOS Google 10/26/2022 Call Trace: <IRQ> __dump_stack lib/dump_stack.c:88
    [inline] dump_stack_lvl+0x1e3/0x2cb lib/dump_stack.c:106 ubsan_epilogue lib/ubsan.c:151 [inline]
    __ubsan_handle_shift_out_of_bounds+0x3a6/0x420 lib/ubsan.c:322 snto32 drivers/hid/hid-core.c:1323 [inline]
    hid_input_fetch_field drivers/hid/hid-core.c:1572 [inline] hid_process_report drivers/hid/hid-core.c:1665
    [inline] hid_report_raw_event+0xd56/0x18b0 drivers/hid/hid-core.c:1998 hid_input_report+0x408/0x4f0
    drivers/hid/hid-core.c:2066 hid_irq_in+0x459/0x690 drivers/hid/usbhid/hid-core.c:284
    __usb_hcd_giveback_urb+0x369/0x530 drivers/usb/core/hcd.c:1671 dummy_timer+0x86b/0x3110
    drivers/usb/gadget/udc/dummy_hcd.c:1988 call_timer_fn+0xf5/0x210 kernel/time/timer.c:1474 expire_timers
    kernel/time/timer.c:1519 [inline] __run_timers+0x76a/0x980 kernel/time/timer.c:1790
    run_timer_softirq+0x63/0xf0 kernel/time/timer.c:1803 __do_softirq+0x277/0x75b kernel/softirq.c:571
    __irq_exit_rcu+0xec/0x170 kernel/softirq.c:650 irq_exit_rcu+0x5/0x20 kernel/softirq.c:662
    sysvec_apic_timer_interrupt+0x91/0xb0 arch/x86/kernel/apic/apic.c:1107
    ====================================================================== If the size of the integer
    (unsigned n) is bigger than 32 in snto32(), shift exponent will be too large for 32-bit type 'int',
    resulting in a shift-out-of-bounds bug. Fix this by adding a check on the size of the integer (unsigned n)
    in snto32(). To add support for n greater than 32 bits, set n to 32, if n is greater than 32.
    (CVE-2022-48978)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48978");

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
