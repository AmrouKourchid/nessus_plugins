#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225694);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48728");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48728");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: IB/hfi1: Fix AIP early init panic An
    early failure in hfi1_ipoib_setup_rn() can lead to the following panic: BUG: unable to handle kernel NULL
    pointer dereference at 00000000000001b0 PGD 0 P4D 0 Oops: 0002 [#1] SMP NOPTI Workqueue: events
    work_for_cpu_fn RIP: 0010:try_to_grab_pending+0x2b/0x140 Code: 1f 44 00 00 41 55 41 54 55 48 89 d5 53 48
    89 fb 9c 58 0f 1f 44 00 00 48 89 c2 fa 66 0f 1f 44 00 00 48 89 55 00 40 84 f6 75 77 <f0> 48 0f ba 2b 00 72
    09 31 c0 5b 5d 41 5c 41 5d c3 48 89 df e8 6c RSP: 0018:ffffb6b3cf7cfa48 EFLAGS: 00010046 RAX:
    0000000000000246 RBX: 00000000000001b0 RCX: 0000000000000000 RDX: 0000000000000246 RSI: 0000000000000000
    RDI: 00000000000001b0 RBP: ffffb6b3cf7cfa70 R08: 0000000000000f09 R09: 0000000000000001 R10:
    0000000000000000 R11: 0000000000000001 R12: 0000000000000000 R13: ffffb6b3cf7cfa90 R14: ffffffff9b2fbfc0
    R15: ffff8a4fdf244690 FS: 0000000000000000(0000) GS:ffff8a527f400000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00000000000001b0 CR3: 00000017e2410003 CR4: 00000000007706f0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: __cancel_work_timer+0x42/0x190 ?
    dev_printk_emit+0x4e/0x70 iowait_cancel_work+0x15/0x30 [hfi1] hfi1_ipoib_txreq_deinit+0x5a/0x220 [hfi1] ?
    dev_err+0x6c/0x90 hfi1_ipoib_netdev_dtor+0x15/0x30 [hfi1] hfi1_ipoib_setup_rn+0x10e/0x150 [hfi1]
    rdma_init_netdev+0x5a/0x80 [ib_core] ? hfi1_ipoib_free_rdma_netdev+0x20/0x20 [hfi1]
    ipoib_intf_init+0x6c/0x350 [ib_ipoib] ipoib_intf_alloc+0x5c/0xc0 [ib_ipoib] ipoib_add_one+0xbe/0x300
    [ib_ipoib] add_client_context+0x12c/0x1a0 [ib_core] enable_device_and_get+0xdc/0x1d0 [ib_core]
    ib_register_device+0x572/0x6b0 [ib_core] rvt_register_device+0x11b/0x220 [rdmavt]
    hfi1_register_ib_device+0x6b4/0x770 [hfi1] do_init_one.isra.20+0x3e3/0x680 [hfi1]
    local_pci_probe+0x41/0x90 work_for_cpu_fn+0x16/0x20 process_one_work+0x1a7/0x360 ?
    create_worker+0x1a0/0x1a0 worker_thread+0x1cf/0x390 ? create_worker+0x1a0/0x1a0 kthread+0x116/0x130 ?
    kthread_flush_work_fn+0x10/0x10 ret_from_fork+0x1f/0x40 The panic happens in hfi1_ipoib_txreq_deinit()
    because there is a NULL deref when hfi1_ipoib_netdev_dtor() is called in this error case.
    hfi1_ipoib_txreq_init() and hfi1_ipoib_rxq_init() are self unwinding so fix by adjusting the error paths
    accordingly. Other changes: - hfi1_ipoib_free_rdma_netdev() is deleted including the free_netdev() since
    the netdev core code deletes calls free_netdev() - The switch to the accelerated entrances is moved to the
    success path. (CVE-2022-48728)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
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
