#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229020);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40904");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40904");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: USB: class: cdc-wdm: Fix CPU lockup
    caused by excessive log messages The syzbot fuzzer found that the interrupt-URB completion callback in the
    cdc-wdm driver was taking too long, and the driver's immediate resubmission of interrupt URBs with -EPROTO
    status combined with the dummy-hcd emulation to cause a CPU lockup: cdc_wdm 1-1:1.0: nonzero urb status
    received: -71 cdc_wdm 1-1:1.0: wdm_int_callback - 0 bytes watchdog: BUG: soft lockup - CPU#0 stuck for
    26s! [syz-executor782:6625] CPU#0 Utilization every 4s during lockup: #1: 98% system, 0% softirq, 3%
    hardirq, 0% idle #2: 98% system, 0% softirq, 3% hardirq, 0% idle #3: 98% system, 0% softirq, 3% hardirq,
    0% idle #4: 98% system, 0% softirq, 3% hardirq, 0% idle #5: 98% system, 1% softirq, 3% hardirq, 0% idle
    Modules linked in: irq event stamp: 73096 hardirqs last enabled at (73095): [<ffff80008037bc00>]
    console_emit_next_record kernel/printk/printk.c:2935 [inline] hardirqs last enabled at (73095):
    [<ffff80008037bc00>] console_flush_all+0x650/0xb74 kernel/printk/printk.c:2994 hardirqs last disabled at
    (73096): [<ffff80008af10b00>] __el1_irq arch/arm64/kernel/entry-common.c:533 [inline] hardirqs last
    disabled at (73096): [<ffff80008af10b00>] el1_interrupt+0x24/0x68 arch/arm64/kernel/entry-common.c:551
    softirqs last enabled at (73048): [<ffff8000801ea530>] softirq_handle_end kernel/softirq.c:400 [inline]
    softirqs last enabled at (73048): [<ffff8000801ea530>] handle_softirqs+0xa60/0xc34 kernel/softirq.c:582
    softirqs last disabled at (73043): [<ffff800080020de8>] __do_softirq+0x14/0x20 kernel/softirq.c:588 CPU: 0
    PID: 6625 Comm: syz-executor782 Tainted: G W 6.10.0-rc2-syzkaller-g8867bbd4a056 #0 Hardware name: Google
    Google Compute Engine/Google Compute Engine, BIOS Google 04/02/2024 Testing showed that the problem did
    not occur if the two error messages -- the first two lines above -- were removed; apparently adding
    material to the kernel log takes a surprisingly large amount of time. In any case, the best approach for
    preventing these lockups and to avoid spamming the log with thousands of error messages per second is to
    ratelimit the two dev_err() calls. Therefore we replace them with dev_err_ratelimited(). (CVE-2024-40904)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40904");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
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
