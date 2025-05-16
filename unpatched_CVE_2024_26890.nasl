#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227607);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26890");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26890");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Bluetooth: btrtl: fix out of bounds
    memory access The problem is detected by KASAN. btrtl driver uses private hci data to store 'struct
    btrealtek_data'. If btrtl driver is used with btusb, then memory for private hci data is allocated in
    btusb. But no private data is allocated after hci_dev, when btrtl is used with hci_h5. This commit adds
    memory allocation for hci_h5 case. ================================================================== BUG:
    KASAN: slab-out-of-bounds in btrtl_initialize+0x6cc/0x958 [btrtl] Write of size 8 at addr ffff00000f5a5748
    by task kworker/u9:0/76 Hardware name: Pine64 PinePhone (1.2) (DT) Workqueue: hci0 hci_power_on
    [bluetooth] Call trace: dump_backtrace+0x9c/0x128 show_stack+0x20/0x38 dump_stack_lvl+0x48/0x60
    print_report+0xf8/0x5d8 kasan_report+0x90/0xd0 __asan_store8+0x9c/0xc0 [btrtl] h5_btrtl_setup+0xd0/0x2f8
    [hci_uart] h5_setup+0x50/0x80 [hci_uart] hci_uart_setup+0xd4/0x260 [hci_uart]
    hci_dev_open_sync+0x1cc/0xf68 [bluetooth] hci_dev_do_open+0x34/0x90 [bluetooth] hci_power_on+0xc4/0x3c8
    [bluetooth] process_one_work+0x328/0x6f0 worker_thread+0x410/0x778 kthread+0x168/0x178
    ret_from_fork+0x10/0x20 Allocated by task 53: kasan_save_stack+0x3c/0x68 kasan_save_track+0x20/0x40
    kasan_save_alloc_info+0x68/0x78 __kasan_kmalloc+0xd4/0xd8 __kmalloc+0x1b4/0x3b0
    hci_alloc_dev_priv+0x28/0xa58 [bluetooth] hci_uart_register_device+0x118/0x4f8 [hci_uart]
    h5_serdev_probe+0xf4/0x178 [hci_uart] serdev_drv_probe+0x54/0xa0 really_probe+0x254/0x588
    __driver_probe_device+0xc4/0x210 driver_probe_device+0x64/0x160 __driver_attach_async_helper+0x88/0x158
    async_run_entry_fn+0xd0/0x388 process_one_work+0x328/0x6f0 worker_thread+0x410/0x778 kthread+0x168/0x178
    ret_from_fork+0x10/0x20 Last potentially related work creation: kasan_save_stack+0x3c/0x68
    __kasan_record_aux_stack+0xb0/0x150 kasan_record_aux_stack_noalloc+0x14/0x20 __queue_work+0x33c/0x960
    queue_work_on+0x98/0xc0 hci_recv_frame+0xc8/0x1e8 [bluetooth] h5_complete_rx_pkt+0x2c8/0x800 [hci_uart]
    h5_rx_payload+0x98/0xb8 [hci_uart] h5_recv+0x158/0x3d8 [hci_uart] hci_uart_receive_buf+0xa0/0xe8
    [hci_uart] ttyport_receive_buf+0xac/0x178 flush_to_ldisc+0x130/0x2c8 process_one_work+0x328/0x6f0
    worker_thread+0x410/0x778 kthread+0x168/0x178 ret_from_fork+0x10/0x20 Second to last potentially related
    work creation: kasan_save_stack+0x3c/0x68 __kasan_record_aux_stack+0xb0/0x150
    kasan_record_aux_stack_noalloc+0x14/0x20 __queue_work+0x788/0x960 queue_work_on+0x98/0xc0
    __hci_cmd_sync_sk+0x23c/0x7a0 [bluetooth] __hci_cmd_sync+0x24/0x38 [bluetooth]
    btrtl_initialize+0x760/0x958 [btrtl] h5_btrtl_setup+0xd0/0x2f8 [hci_uart] h5_setup+0x50/0x80 [hci_uart]
    hci_uart_setup+0xd4/0x260 [hci_uart] hci_dev_open_sync+0x1cc/0xf68 [bluetooth] hci_dev_do_open+0x34/0x90
    [bluetooth] hci_power_on+0xc4/0x3c8 [bluetooth] process_one_work+0x328/0x6f0 worker_thread+0x410/0x778
    kthread+0x168/0x178 ret_from_fork+0x10/0x20
    ================================================================== (CVE-2024-26890)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26890");

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
