#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229333);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46766");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46766");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ice: move netif_queue_set_napi to
    rtnl-protected sections Currently, netif_queue_set_napi() is called from ice_vsi_rebuild() that is not
    rtnl-locked when called from the reset. This creates the need to take the rtnl_lock just for a single
    function and complicates the synchronization with .ndo_bpf. At the same time, there no actual need to fill
    napi-to-queue information at this exact point. Fill napi-to-queue information when opening the VSI and
    clear it when the VSI is being closed. Those routines are already rtnl-locked. Also, rewrite napi-to-queue
    assignment in a way that prevents inclusion of XDP queues, as this leads to out-of-bounds writes, such as
    one below. [ +0.000004] BUG: KASAN: slab-out-of-bounds in netif_queue_set_napi+0x1c2/0x1e0 [ +0.000012]
    Write of size 8 at addr ffff889881727c80 by task bash/7047 [ +0.000006] CPU: 24 PID: 7047 Comm: bash Not
    tainted 6.10.0-rc2+ #2 [ +0.000004] Hardware name: Intel Corporation S2600WFT/S2600WFT, BIOS
    SE5C620.86B.02.01.0014.082620210524 08/26/2021 [ +0.000003] Call Trace: [ +0.000003] <TASK> [ +0.000002]
    dump_stack_lvl+0x60/0x80 [ +0.000007] print_report+0xce/0x630 [ +0.000007] ?
    __pfx__raw_spin_lock_irqsave+0x10/0x10 [ +0.000007] ? __virt_addr_valid+0x1c9/0x2c0 [ +0.000005] ?
    netif_queue_set_napi+0x1c2/0x1e0 [ +0.000003] kasan_report+0xe9/0x120 [ +0.000004] ?
    netif_queue_set_napi+0x1c2/0x1e0 [ +0.000004] netif_queue_set_napi+0x1c2/0x1e0 [ +0.000005]
    ice_vsi_close+0x161/0x670 [ice] [ +0.000114] ice_dis_vsi+0x22f/0x270 [ice] [ +0.000095]
    ice_pf_dis_all_vsi.constprop.0+0xae/0x1c0 [ice] [ +0.000086] ice_prepare_for_reset+0x299/0x750 [ice] [
    +0.000087] pci_dev_save_and_disable+0x82/0xd0 [ +0.000006] pci_reset_function+0x12d/0x230 [ +0.000004]
    reset_store+0xa0/0x100 [ +0.000006] ? __pfx_reset_store+0x10/0x10 [ +0.000002] ?
    __pfx_mutex_lock+0x10/0x10 [ +0.000004] ? __check_object_size+0x4c1/0x640 [ +0.000007]
    kernfs_fop_write_iter+0x30b/0x4a0 [ +0.000006] vfs_write+0x5d6/0xdf0 [ +0.000005] ? fd_install+0x180/0x350
    [ +0.000005] ? __pfx_vfs_write+0x10/0xA10 [ +0.000004] ? do_fcntl+0x52c/0xcd0 [ +0.000004] ?
    kasan_save_track+0x13/0x60 [ +0.000003] ? kasan_save_free_info+0x37/0x60 [ +0.000006]
    ksys_write+0xfa/0x1d0 [ +0.000003] ? __pfx_ksys_write+0x10/0x10 [ +0.000002] ? __x64_sys_fcntl+0x121/0x180
    [ +0.000004] ? _raw_spin_lock+0x87/0xe0 [ +0.000005] do_syscall_64+0x80/0x170 [ +0.000007] ?
    _raw_spin_lock+0x87/0xe0 [ +0.000004] ? __pfx__raw_spin_lock+0x10/0x10 [ +0.000003] ?
    file_close_fd_locked+0x167/0x230 [ +0.000005] ? syscall_exit_to_user_mode+0x7d/0x220 [ +0.000005] ?
    do_syscall_64+0x8c/0x170 [ +0.000004] ? do_syscall_64+0x8c/0x170 [ +0.000003] ? do_syscall_64+0x8c/0x170 [
    +0.000003] ? fput+0x1a/0x2c0 [ +0.000004] ? filp_close+0x19/0x30 [ +0.000004] ? do_dup2+0x25a/0x4c0 [
    +0.000004] ? __x64_sys_dup2+0x6e/0x2e0 [ +0.000002] ? syscall_exit_to_user_mode+0x7d/0x220 [ +0.000004] ?
    do_syscall_64+0x8c/0x170 [ +0.000003] ? __count_memcg_events+0x113/0x380 [ +0.000005] ?
    handle_mm_fault+0x136/0x820 [ +0.000005] ? do_user_addr_fault+0x444/0xa80 [ +0.000004] ?
    clear_bhb_loop+0x25/0x80 [ +0.000004] ? clear_bhb_loop+0x25/0x80 [ +0.000002]
    entry_SYSCALL_64_after_hwframe+0x76/0x7e [ +0.000005] RIP: 0033:0x7f2033593154 (CVE-2024-46766)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46766");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
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
