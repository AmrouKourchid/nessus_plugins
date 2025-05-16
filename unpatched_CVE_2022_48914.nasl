#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225569);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48914");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48914");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: xen/netfront: destroy queues before
    real_num_tx_queues is zeroed xennet_destroy_queues() relies on info->netdev->real_num_tx_queues to delete
    queues. Since d7dac083414eb5bb99a6d2ed53dc2c1b405224e5 (net-sysfs: update the queue counts in the
    unregistration path), unregister_netdev() indirectly sets real_num_tx_queues to 0. Those two facts
    together means, that xennet_destroy_queues() called from xennet_remove() cannot do its job, because it's
    called after unregister_netdev(). This results in kfree-ing queues that are still linked in napi, which
    ultimately crashes: BUG: kernel NULL pointer dereference, address: 0000000000000000 #PF: supervisor read
    access in kernel mode #PF: error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: 0000 [#1] PREEMPT SMP
    PTI CPU: 1 PID: 52 Comm: xenwatch Tainted: G W 5.16.10-1.32.fc32.qubes.x86_64+ #226 RIP:
    0010:free_netdev+0xa3/0x1a0 Code: ff 48 89 df e8 2e e9 00 00 48 8b 43 50 48 8b 08 48 8d b8 a0 fe ff ff 48
    8d a9 a0 fe ff ff 49 39 c4 75 26 eb 47 e8 ed c1 66 ff <48> 8b 85 60 01 00 00 48 8d 95 60 01 00 00 48 89 ef
    48 2d 60 01 00 RSP: 0000:ffffc90000bcfd00 EFLAGS: 00010286 RAX: 0000000000000000 RBX: ffff88800edad000
    RCX: 0000000000000000 RDX: 0000000000000001 RSI: ffffc90000bcfc30 RDI: 00000000ffffffff RBP:
    fffffffffffffea0 R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000001
    R12: ffff88800edad050 R13: ffff8880065f8f88 R14: 0000000000000000 R15: ffff8880066c6680 FS:
    0000000000000000(0000) GS:ffff8880f3300000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 0000000000000000 CR3: 00000000e998c006 CR4: 00000000003706e0 Call Trace: <TASK>
    xennet_remove+0x13d/0x300 [xen_netfront] xenbus_dev_remove+0x6d/0xf0 __device_release_driver+0x17a/0x240
    device_release_driver+0x24/0x30 bus_remove_device+0xd8/0x140 device_del+0x18b/0x410 ?
    _raw_spin_unlock+0x16/0x30 ? klist_iter_exit+0x14/0x20 ? xenbus_dev_request_and_reply+0x80/0x80
    device_unregister+0x13/0x60 xenbus_dev_changed+0x18e/0x1f0 xenwatch_thread+0xc0/0x1a0 ?
    do_wait_intr_irq+0xa0/0xa0 kthread+0x16b/0x190 ? set_kthread_struct+0x40/0x40 ret_from_fork+0x22/0x30
    </TASK> Fix this by calling xennet_destroy_queues() from xennet_uninit(), when real_num_tx_queues is still
    available. This ensures that queues are destroyed when real_num_tx_queues is set to 0, regardless of how
    unregister_netdev() was called. Originally reported at https://github.com/QubesOS/qubes-issues/issues/7257
    (CVE-2022-48914)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48914");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
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
