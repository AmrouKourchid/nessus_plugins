#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225453);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48984");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48984");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: can: slcan: fix freed work crash The
    LTP test pty03 is causing a crash in slcan: BUG: kernel NULL pointer dereference, address:
    0000000000000008 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD
    0 P4D 0 Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 0 PID: 348 Comm: kworker/0:3 Not tainted 6.0.8-1-default #1
    openSUSE Tumbleweed 9d20364b934f5aab0a9bdf84e8f45cfdfae39dab Hardware name: QEMU Standard PC (i440FX +
    PIIX, 1996), BIOS rel-1.15.0-0-g2dd4b9b-rebuilt.opensuse.org 04/01/2014 Workqueue: 0x0 (events) RIP:
    0010:process_one_work (/home/rich/kernel/linux/kernel/workqueue.c:706
    /home/rich/kernel/linux/kernel/workqueue.c:2185) Code: 49 89 ff 41 56 41 55 41 54 55 53 48 89 f3 48 83 ec
    10 48 8b 06 48 8b 6f 48 49 89 c4 45 30 e4 a8 04 b8 00 00 00 00 4c 0f 44 e0 <49> 8b 44 24 08 44 8b a8 00 01
    00 00 41 83 e5 20 f6 45 10 04 75 0e RSP: 0018:ffffaf7b40f47e98 EFLAGS: 00010046 RAX: 0000000000000000 RBX:
    ffff9d644e1b8b48 RCX: ffff9d649e439968 RDX: 00000000ffff8455 RSI: ffff9d644e1b8b48 RDI: ffff9d64764aa6c0
    RBP: ffff9d649e4335c0 R08: 0000000000000c00 R09: ffff9d64764aa734 R10: 0000000000000007 R11:
    0000000000000001 R12: 0000000000000000 R13: ffff9d649e4335e8 R14: ffff9d64490da780 R15: ffff9d64764aa6c0
    FS: 0000000000000000(0000) GS:ffff9d649e400000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 0000000000000008 CR3: 0000000036424000 CR4: 00000000000006f0 Call Trace: <TASK>
    worker_thread (/home/rich/kernel/linux/kernel/workqueue.c:2436) kthread
    (/home/rich/kernel/linux/kernel/kthread.c:376) ret_from_fork
    (/home/rich/kernel/linux/arch/x86/entry/entry_64.S:312) Apparently, the slcan's tx_work is freed while
    being scheduled. While slcan_netdev_close() (netdev side) calls flush_work(&sl->tx_work), slcan_close()
    (tty side) does not. So when the netdev is never set UP, but the tty is stuffed with bytes and forced to
    wakeup write, the work is scheduled, but never flushed. So add an additional flush_work() to slcan_close()
    to be sure the work is flushed under all circumstances. The Fixes commit below moved flush_work() from
    slcan_close() to slcan_netdev_close(). What was the rationale behind it? Maybe we can drop the one in
    slcan_netdev_close()? I see the same pattern in can327. So it perhaps needs the very same fix.
    (CVE-2022-48984)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48984");

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
