#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230127);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47449");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47449");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ice: fix locking for Tx timestamp
    tracking flush Commit 4dd0d5c33c3e (ice: add lock around Tx timestamp tracker flush) added a lock around
    the Tx timestamp tracker flow which is used to cleanup any left over SKBs and prepare for device removal.
    This lock is problematic because it is being held around a call to ice_clear_phy_tstamp. The clear
    function takes a mutex to send a PHY write command to firmware. This could lead to a deadlock if the mutex
    actually sleeps, and causes the following warning on a kernel with preemption debugging enabled: [
    715.419426] BUG: sleeping function called from invalid context at kernel/locking/mutex.c:573 [ 715.427900]
    in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 3100, name: rmmod [ 715.435652] INFO: lockdep is
    turned off. [ 715.439591] Preemption disabled at: [ 715.439594] [<0000000000000000>] 0x0 [ 715.446678]
    CPU: 52 PID: 3100 Comm: rmmod Tainted: G W OE 5.15.0-rc4+ #42 bdd7ec3018e725f159ca0d372ce8c2c0e784891c [
    715.458058] Hardware name: Intel Corporation S2600STQ/S2600STQ, BIOS SE5C620.86B.02.01.0010.010620200716
    01/06/2020 [ 715.468483] Call Trace: [ 715.470940] dump_stack_lvl+0x6a/0x9a [ 715.474613]
    ___might_sleep.cold+0x224/0x26a [ 715.478895] __mutex_lock+0xb3/0x1440 [ 715.482569] ?
    stack_depot_save+0x378/0x500 [ 715.486763] ? ice_sq_send_cmd+0x78/0x14c0 [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.494979] ? kfree+0xc1/0x520 [ 715.498128] ?
    mutex_lock_io_nested+0x12a0/0x12a0 [ 715.502837] ? kasan_set_free_info+0x20/0x30 [ 715.507110] ?
    __kasan_slab_free+0x10b/0x140 [ 715.511385] ? slab_free_freelist_hook+0xc7/0x220 [ 715.516092] ?
    kfree+0xc1/0x520 [ 715.519235] ? ice_deinit_lag+0x16c/0x220 [ice 9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d]
    [ 715.527359] ? ice_remove+0x1cf/0x6a0 [ice 9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.535133] ?
    pci_device_remove+0xab/0x1d0 [ 715.539318] ? __device_release_driver+0x35b/0x690 [ 715.544110] ?
    driver_detach+0x214/0x2f0 [ 715.548035] ? bus_remove_driver+0x11d/0x2f0 [ 715.552309] ?
    pci_unregister_driver+0x26/0x250 [ 715.556840] ? ice_module_exit+0xc/0x2f [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.564799] ? __do_sys_delete_module.constprop.0+0x2d8/0x4e0 [
    715.570554] ? do_syscall_64+0x3b/0x90 [ 715.574303] ? entry_SYSCALL_64_after_hwframe+0x44/0xae [
    715.579529] ? start_flush_work+0x542/0x8f0 [ 715.583719] ? ice_sq_send_cmd+0x78/0x14c0 [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.591923] ice_sq_send_cmd+0x78/0x14c0 [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.599960] ? wait_for_completion_io+0x250/0x250 [ 715.604662]
    ? lock_acquire+0x196/0x200 [ 715.608504] ? do_raw_spin_trylock+0xa5/0x160 [ 715.612864]
    ice_sbq_rw_reg+0x1e6/0x2f0 [ice 9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.620813] ?
    ice_reset+0x130/0x130 [ice 9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.628497] ?
    __debug_check_no_obj_freed+0x1e8/0x3c0 [ 715.633550] ? trace_hardirqs_on+0x1c/0x130 [ 715.637748]
    ice_write_phy_reg_e810+0x70/0xf0 [ice 9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.646220] ?
    do_raw_spin_trylock+0xa5/0x160 [ 715.650581] ? ice_ptp_release+0x910/0x910 [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.658797] ? ice_ptp_release+0x255/0x910 [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.667013] ice_clear_phy_tstamp+0x2c/0x110 [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.675403] ice_ptp_release+0x408/0x910 [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.683440] ice_remove+0x560/0x6a0 [ice
    9a7e1ec00971c89ecd3fe0d4dc7da2b3786a421d] [ 715.691037] ? _raw_spin_unlock_irqrestore+0x46/0x73 [
    715.696005] pci_device_remove+0xab/0x1d0 [ 715.700018] __device_release_driver+0x35b/0x690 [ 715.704637]
    driver_detach+0x214/0x2f0 [ 715.708389] bus_remove_driver+0x11d/0x2f0 [ 715.712489]
    pci_unregister_driver+0x26/0x250 [ 71 ---truncated--- (CVE-2021-47449)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
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
