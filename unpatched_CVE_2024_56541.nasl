#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231311);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-56541");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-56541");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: ath12k: fix use-after-free in
    ath12k_dp_cc_cleanup() During ath12k module removal, in ath12k_core_deinit(), ath12k_mac_destroy() un-
    registers ah->hw from mac80211 and frees the ah->hw as well as all the ar's in it. After this
    ath12k_core_soc_destroy()-> ath12k_dp_free()-> ath12k_dp_cc_cleanup() tries to access one of the freed
    ar's from pending skb. This is because during mac destroy, driver failed to flush few data packets, which
    were accessed later in ath12k_dp_cc_cleanup() and freed, but using ar from the packet led to this use-
    after-free. BUG: KASAN: use-after-free in ath12k_dp_cc_cleanup.part.0+0x5e2/0xd40 [ath12k] Write of size 4
    at addr ffff888150bd3514 by task modprobe/8926 CPU: 0 UID: 0 PID: 8926 Comm: modprobe Not tainted
    6.11.0-rc2-wt-ath+ #1746 Hardware name: Intel(R) Client Systems NUC8i7HVK/NUC8i7HVB, BIOS
    HNKBLi70.86A.0067.2021.0528.1339 05/28/2021 Call Trace: <TASK> dump_stack_lvl+0x7d/0xe0
    print_address_description.constprop.0+0x33/0x3a0 print_report+0xb5/0x260 ? kasan_addr_to_slab+0x24/0x80
    kasan_report+0xd8/0x110 ? ath12k_dp_cc_cleanup.part.0+0x5e2/0xd40 [ath12k] ?
    ath12k_dp_cc_cleanup.part.0+0x5e2/0xd40 [ath12k] kasan_check_range+0xf3/0x1a0
    __kasan_check_write+0x14/0x20 ath12k_dp_cc_cleanup.part.0+0x5e2/0xd40 [ath12k] ath12k_dp_free+0x178/0x420
    [ath12k] ath12k_core_stop+0x176/0x200 [ath12k] ath12k_core_deinit+0x13f/0x210 [ath12k]
    ath12k_pci_remove+0xad/0x1c0 [ath12k] pci_device_remove+0x9b/0x1b0 device_remove+0xbf/0x150
    device_release_driver_internal+0x3c3/0x580 ? __kasan_check_read+0x11/0x20 driver_detach+0xc4/0x190
    bus_remove_driver+0x130/0x2a0 driver_unregister+0x68/0x90 pci_unregister_driver+0x24/0x240 ?
    find_module_all+0x13e/0x1e0 ath12k_pci_exit+0x10/0x20 [ath12k] __do_sys_delete_module+0x32c/0x580 ?
    module_flags+0x2f0/0x2f0 ? kmem_cache_free+0xf0/0x410 ? __fput+0x56f/0xab0 ? __fput+0x56f/0xab0 ?
    debug_smp_processor_id+0x17/0x20 __x64_sys_delete_module+0x4f/0x70 x64_sys_call+0x522/0x9f0
    do_syscall_64+0x64/0x130 entry_SYSCALL_64_after_hwframe+0x4b/0x53 RIP: 0033:0x7f8182c6ac8b Commit
    24de1b7b231c (wifi: ath12k: fix flush failure in recovery scenarios) added the change to decrement the
    pending packets count in case of recovery which make sense as ah->hw as well all ar's in it are intact
    during recovery, but during core deinit there is no use in decrementing packets count or waking up the
    empty waitq as the module is going to be removed also ar's from pending skb's can't be used and the
    packets should just be released back. To fix this, avoid accessing ar from skb->cb when driver is being
    unregistered. Tested-on: QCN9274 hw2.0 PCI WLAN.WBE.1.1.1-00214-QCAHKSWPL_SILICONZ-1 Tested-on: WCN7850
    hw2.0 PCI WLAN.HMT.1.0.c5-00481-QCAHMTSWPL_V1.0_V2.0_SILICONZ-3 (CVE-2024-56541)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-56541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "24.04"
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
