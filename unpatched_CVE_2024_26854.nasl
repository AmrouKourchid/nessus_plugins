#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228149);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26854");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26854");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ice: fix uninitialized dplls mutex
    usage The pf->dplls.lock mutex is initialized too late, after its first use. Move it to the top of
    ice_dpll_init. Note that the err_exit error path destroys the mutex. And the mutex is the last thing
    destroyed in ice_dpll_deinit. This fixes the following warning with CONFIG_DEBUG_MUTEXES: ice
    0000:10:00.0: The DDP package was successfully loaded: ICE OS Default Package version 1.3.36.0 ice
    0000:10:00.0: 252.048 Gb/s available PCIe bandwidth (16.0 GT/s PCIe x16 link) ice 0000:10:00.0: PTP init
    successful ------------[ cut here ]------------ DEBUG_LOCKS_WARN_ON(lock->magic != lock) WARNING: CPU: 0
    PID: 410 at kernel/locking/mutex.c:587 __mutex_lock+0x773/0xd40 Modules linked in: crct10dif_pclmul
    crc32_pclmul crc32c_intel polyval_clmulni polyval_generic ice(+) nvme nvme_c> CPU: 0 PID: 410 Comm:
    kworker/0:4 Not tainted 6.8.0-rc5+ #3 Hardware name: HPE ProLiant DL110 Gen10 Plus/ProLiant DL110 Gen10
    Plus, BIOS U56 10/19/2023 Workqueue: events work_for_cpu_fn RIP: 0010:__mutex_lock+0x773/0xd40 Code: c0 0f
    84 1d f9 ff ff 44 8b 35 0d 9c 69 01 45 85 f6 0f 85 0d f9 ff ff 48 c7 c6 12 a2 a9 85 48 c7 c7 12 f1 a> RSP:
    0018:ff7eb1a3417a7ae0 EFLAGS: 00010286 RAX: 0000000000000000 RBX: 0000000000000002 RCX: 0000000000000000
    RDX: 0000000000000002 RSI: ffffffff85ac2bff RDI: 00000000ffffffff RBP: ff7eb1a3417a7b80 R08:
    0000000000000000 R09: 00000000ffffbfff R10: ff7eb1a3417a7978 R11: ff32b80f7fd2e568 R12: 0000000000000000
    R13: 0000000000000000 R14: 0000000000000000 R15: ff32b7f02c50e0d8 FS: 0000000000000000(0000)
    GS:ff32b80efe800000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    000055b5852cc000 CR3: 000000003c43a004 CR4: 0000000000771ef0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554
    Call Trace: <TASK> ? __warn+0x84/0x170 ? __mutex_lock+0x773/0xd40 ? report_bug+0x1c7/0x1d0 ?
    prb_read_valid+0x1b/0x30 ? handle_bug+0x42/0x70 ? exc_invalid_op+0x18/0x70 ? asm_exc_invalid_op+0x1a/0x20
    ? __mutex_lock+0x773/0xd40 ? rcu_is_watching+0x11/0x50 ? __kmalloc_node_track_caller+0x346/0x490 ?
    ice_dpll_lock_status_get+0x28/0x50 [ice] ? __pfx_ice_dpll_lock_status_get+0x10/0x10 [ice] ?
    ice_dpll_lock_status_get+0x28/0x50 [ice] ice_dpll_lock_status_get+0x28/0x50 [ice]
    dpll_device_get_one+0x14f/0x2e0 dpll_device_event_send+0x7d/0x150 dpll_device_register+0x124/0x180
    ice_dpll_init_dpll+0x7b/0xd0 [ice] ice_dpll_init+0x224/0xa40 [ice] ? _dev_info+0x70/0x90
    ice_load+0x468/0x690 [ice] ice_probe+0x75b/0xa10 [ice] ? _raw_spin_unlock_irqrestore+0x4f/0x80 ?
    process_one_work+0x1a3/0x500 local_pci_probe+0x47/0xa0 work_for_cpu_fn+0x17/0x30
    process_one_work+0x20d/0x500 worker_thread+0x1df/0x3e0 ? __pfx_worker_thread+0x10/0x10 kthread+0x103/0x140
    ? __pfx_kthread+0x10/0x10 ret_from_fork+0x31/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30
    </TASK> irq event stamp: 125197 hardirqs last enabled at (125197): [<ffffffff8416409d>]
    finish_task_switch.isra.0+0x12d/0x3d0 hardirqs last disabled at (125196): [<ffffffff85134044>]
    __schedule+0xea4/0x19f0 softirqs last enabled at (105334): [<ffffffff84e1e65a>]
    napi_get_frags_check+0x1a/0x60 softirqs last disabled at (105332): [<ffffffff84e1e65a>]
    napi_get_frags_check+0x1a/0x60 ---[ end trace 0000000000000000 ]--- (CVE-2024-26854)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26854");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
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
