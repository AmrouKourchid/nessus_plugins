#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228300);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26891");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26891");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: iommu/vt-d: Don't issue ATS
    Invalidation request when device is disconnected For those endpoint devices connect to system via hotplug
    capable ports, users could request a hot reset to the device by flapping device's link through setting the
    slot's link control register, as pciehp_ist() DLLSC interrupt sequence response, pciehp will unload the
    device driver and then power it off. thus cause an IOMMU device-TLB invalidation (Intel VT-d spec, or ATS
    Invalidation in PCIe spec r6.1) request for non-existence target device to be sent and deadly loop to
    retry that request after ITE fault triggered in interrupt context. That would cause following continuous
    hard lockup warning and system hang [ 4211.433662] pcieport 0000:17:01.0: pciehp: Slot(108): Link Down [
    4211.433664] pcieport 0000:17:01.0: pciehp: Slot(108): Card not present [ 4223.822591] NMI watchdog:
    Watchdog detected hard LOCKUP on cpu 144 [ 4223.822622] CPU: 144 PID: 1422 Comm: irq/57-pciehp Kdump:
    loaded Tainted: G S OE kernel version xxxx [ 4223.822623] Hardware name: vendorname xxxx 666-106, BIOS
    01.01.02.03.01 05/15/2023 [ 4223.822623] RIP: 0010:qi_submit_sync+0x2c0/0x490 [ 4223.822624] Code: 48 be
    00 00 00 00 00 08 00 00 49 85 74 24 20 0f 95 c1 48 8b 57 10 83 c1 04 83 3c 1a 03 0f 84 a2 01 00 00 49 8b
    04 24 8b 70 34 <40> f6 c6 1 0 74 17 49 8b 04 24 8b 80 80 00 00 00 89 c2 d3 fa 41 39 [ 4223.822624] RSP:
    0018:ffffc4f074f0bbb8 EFLAGS: 00000093 [ 4223.822625] RAX: ffffc4f040059000 RBX: 0000000000000014 RCX:
    0000000000000005 [ 4223.822625] RDX: ffff9f3841315800 RSI: 0000000000000000 RDI: ffff9f38401a8340 [
    4223.822625] RBP: ffff9f38401a8340 R08: ffffc4f074f0bc00 R09: 0000000000000000 [ 4223.822626] R10:
    0000000000000010 R11: 0000000000000018 R12: ffff9f384005e200 [ 4223.822626] R13: 0000000000000004 R14:
    0000000000000046 R15: 0000000000000004 [ 4223.822626] FS: 0000000000000000(0000) GS:ffffa237ae400000(0000)
    knlGS:0000000000000000 [ 4223.822627] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 4223.822627] CR2:
    00007ffe86515d80 CR3: 000002fd3000a001 CR4: 0000000000770ee0 [ 4223.822627] DR0: 0000000000000000 DR1:
    0000000000000000 DR2: 0000000000000000 [ 4223.822628] DR3: 0000000000000000 DR6: 00000000fffe07f0 DR7:
    0000000000000400 [ 4223.822628] PKRU: 55555554 [ 4223.822628] Call Trace: [ 4223.822628]
    qi_flush_dev_iotlb+0xb1/0xd0 [ 4223.822628] __dmar_remove_one_dev_info+0x224/0x250 [ 4223.822629]
    dmar_remove_one_dev_info+0x3e/0x50 [ 4223.822629] intel_iommu_release_device+0x1f/0x30 [ 4223.822629]
    iommu_release_device+0x33/0x60 [ 4223.822629] iommu_bus_notifier+0x7f/0x90 [ 4223.822630]
    blocking_notifier_call_chain+0x60/0x90 [ 4223.822630] device_del+0x2e5/0x420 [ 4223.822630]
    pci_remove_bus_device+0x70/0x110 [ 4223.822630] pciehp_unconfigure_device+0x7c/0x130 [ 4223.822631]
    pciehp_disable_slot+0x6b/0x100 [ 4223.822631] pciehp_handle_presence_or_link_change+0xd8/0x320 [
    4223.822631] pciehp_ist+0x176/0x180 [ 4223.822631] ? irq_finalize_oneshot.part.50+0x110/0x110 [
    4223.822632] irq_thread_fn+0x19/0x50 [ 4223.822632] irq_thread+0x104/0x190 [ 4223.822632] ?
    irq_forced_thread_fn+0x90/0x90 [ 4223.822632] ? irq_thread_check_affinity+0xe0/0xe0 [ 4223.822633]
    kthread+0x114/0x130 [ 4223.822633] ? __kthread_cancel_work+0x40/0x40 [ 4223.822633]
    ret_from_fork+0x1f/0x30 [ 4223.822633] Kernel panic - not syncing: Hard LOCKUP [ 4223.822634] CPU: 144
    PID: 1422 Comm: irq/57-pciehp Kdump: loaded Tainted: G S OE kernel version xxxx [ 4223.822634] Hardware
    name: vendorname xxxx 666-106, BIOS 01.01.02.03.01 05/15/2023 [ 4223.822634] Call Trace: [ 4223.822634]
    <NMI> [ 4223.822635] dump_stack+0x6d/0x88 [ 4223.822635] panic+0x101/0x2d0 [ 4223.822635] ?
    ret_from_fork+0x11/0x30 [ 4223.822635] nmi_panic.cold.14+0xc/0xc [ 4223.822636]
    watchdog_overflow_callback.cold.8+0x6d/0x81 [ 4223.822636] __perf_event_overflow+0x4f/0xf0 [ 4223.822636]
    handle_pmi_common ---truncated--- (CVE-2024-26891)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26891");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
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
