#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228661);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-39502");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-39502");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ionic: fix use after netif_napi_del()
    When queues are started, netif_napi_add() and napi_enable() are called. If there are 4 queues and only 3
    queues are used for the current configuration, only 3 queues' napi should be registered and enabled. The
    ionic_qcq_enable() checks whether the .poll pointer is not NULL for enabling only the using queue' napi.
    Unused queues' napi will not be registered by netif_napi_add(), so the .poll pointer indicates NULL. But
    it couldn't distinguish whether the napi was unregistered or not because netif_napi_del() doesn't reset
    the .poll pointer to NULL. So, ionic_qcq_enable() calls napi_enable() for the queue, which was
    unregistered by netif_napi_del(). Reproducer: ethtool -L <interface name> rx 1 tx 1 combined 0 ethtool -L
    <interface name> rx 0 tx 0 combined 1 ethtool -L <interface name> rx 0 tx 0 combined 4 Splat looks like:
    kernel BUG at net/core/dev.c:6666! Oops: invalid opcode: 0000 [#1] PREEMPT SMP NOPTI CPU: 3 PID: 1057
    Comm: kworker/3:3 Not tainted 6.10.0-rc2+ #16 Workqueue: events ionic_lif_deferred_work [ionic] RIP:
    0010:napi_enable+0x3b/0x40 Code: 48 89 c2 48 83 e2 f6 80 b9 61 09 00 00 00 74 0d 48 83 bf 60 01 00 00 00
    74 03 80 ce 01 f0 4f RSP: 0018:ffffb6ed83227d48 EFLAGS: 00010246 RAX: 0000000000000000 RBX:
    ffff97560cda0828 RCX: 0000000000000029 RDX: 0000000000000001 RSI: 0000000000000000 RDI: ffff97560cda0a28
    RBP: ffffb6ed83227d50 R08: 0000000000000400 R09: 0000000000000001 R10: 0000000000000001 R11:
    0000000000000001 R12: 0000000000000000 R13: ffff97560ce3c1a0 R14: 0000000000000000 R15: ffff975613ba0a20
    FS: 0000000000000000(0000) GS:ffff975d5f780000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 00007f8f734ee200 CR3: 0000000103e50000 CR4: 00000000007506f0 PKRU: 55555554
    Call Trace: <TASK> ? die+0x33/0x90 ? do_trap+0xd9/0x100 ? napi_enable+0x3b/0x40 ? do_error_trap+0x83/0xb0
    ? napi_enable+0x3b/0x40 ? napi_enable+0x3b/0x40 ? exc_invalid_op+0x4e/0x70 ? napi_enable+0x3b/0x40 ?
    asm_exc_invalid_op+0x16/0x20 ? napi_enable+0x3b/0x40 ionic_qcq_enable+0xb7/0x180 [ionic
    59bdfc8a035436e1c4224ff7d10789e3f14643f8] ionic_start_queues+0xc4/0x290 [ionic
    59bdfc8a035436e1c4224ff7d10789e3f14643f8] ionic_link_status_check+0x11c/0x170 [ionic
    59bdfc8a035436e1c4224ff7d10789e3f14643f8] ionic_lif_deferred_work+0x129/0x280 [ionic
    59bdfc8a035436e1c4224ff7d10789e3f14643f8] process_one_work+0x145/0x360 worker_thread+0x2bb/0x3d0 ?
    __pfx_worker_thread+0x10/0x10 kthread+0xcc/0x100 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x2d/0x50 ?
    __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1a/0x30 (CVE-2024-39502)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39502");

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
