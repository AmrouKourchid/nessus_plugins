#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225233);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48919");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48919");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: cifs: fix double free race when mount
    fails in cifs_get_root() When cifs_get_root() fails during cifs_smb3_do_mount() we call
    deactivate_locked_super() which eventually will call delayed_free() which will free the context. In this
    situation we should not proceed to enter the out: section in cifs_smb3_do_mount() and free the same
    resources a second time. [Thu Feb 10 12:59:06 2022] BUG: KASAN: use-after-free in
    rcu_cblist_dequeue+0x32/0x60 [Thu Feb 10 12:59:06 2022] Read of size 8 at addr ffff888364f4d110 by task
    swapper/1/0 [Thu Feb 10 12:59:06 2022] CPU: 1 PID: 0 Comm: swapper/1 Tainted: G OE 5.17.0-rc3+ #4 [Thu Feb
    10 12:59:06 2022] Hardware name: Microsoft Corporation Virtual Machine/Virtual Machine, BIOS Hyper-V UEFI
    Release v4.0 12/17/2019 [Thu Feb 10 12:59:06 2022] Call Trace: [Thu Feb 10 12:59:06 2022] <IRQ> [Thu Feb
    10 12:59:06 2022] dump_stack_lvl+0x5d/0x78 [Thu Feb 10 12:59:06 2022]
    print_address_description.constprop.0+0x24/0x150 [Thu Feb 10 12:59:06 2022] ? rcu_cblist_dequeue+0x32/0x60
    [Thu Feb 10 12:59:06 2022] kasan_report.cold+0x7d/0x117 [Thu Feb 10 12:59:06 2022] ?
    rcu_cblist_dequeue+0x32/0x60 [Thu Feb 10 12:59:06 2022] __asan_load8+0x86/0xa0 [Thu Feb 10 12:59:06 2022]
    rcu_cblist_dequeue+0x32/0x60 [Thu Feb 10 12:59:06 2022] rcu_core+0x547/0xca0 [Thu Feb 10 12:59:06 2022] ?
    call_rcu+0x3c0/0x3c0 [Thu Feb 10 12:59:06 2022] ? __this_cpu_preempt_check+0x13/0x20 [Thu Feb 10 12:59:06
    2022] ? lock_is_held_type+0xea/0x140 [Thu Feb 10 12:59:06 2022] rcu_core_si+0xe/0x10 [Thu Feb 10 12:59:06
    2022] __do_softirq+0x1d4/0x67b [Thu Feb 10 12:59:06 2022] __irq_exit_rcu+0x100/0x150 [Thu Feb 10 12:59:06
    2022] irq_exit_rcu+0xe/0x30 [Thu Feb 10 12:59:06 2022] sysvec_hyperv_stimer0+0x9d/0xc0 ... [Thu Feb 10
    12:59:07 2022] Freed by task 58179: [Thu Feb 10 12:59:07 2022] kasan_save_stack+0x26/0x50 [Thu Feb 10
    12:59:07 2022] kasan_set_track+0x25/0x30 [Thu Feb 10 12:59:07 2022] kasan_set_free_info+0x24/0x40 [Thu Feb
    10 12:59:07 2022] ____kasan_slab_free+0x137/0x170 [Thu Feb 10 12:59:07 2022] __kasan_slab_free+0x12/0x20
    [Thu Feb 10 12:59:07 2022] slab_free_freelist_hook+0xb3/0x1d0 [Thu Feb 10 12:59:07 2022] kfree+0xcd/0x520
    [Thu Feb 10 12:59:07 2022] cifs_smb3_do_mount+0x149/0xbe0 [cifs] [Thu Feb 10 12:59:07 2022]
    smb3_get_tree+0x1a0/0x2e0 [cifs] [Thu Feb 10 12:59:07 2022] vfs_get_tree+0x52/0x140 [Thu Feb 10 12:59:07
    2022] path_mount+0x635/0x10c0 [Thu Feb 10 12:59:07 2022] __x64_sys_mount+0x1bf/0x210 [Thu Feb 10 12:59:07
    2022] do_syscall_64+0x5c/0xc0 [Thu Feb 10 12:59:07 2022] entry_SYSCALL_64_after_hwframe+0x44/0xae [Thu Feb
    10 12:59:07 2022] Last potentially related work creation: [Thu Feb 10 12:59:07 2022]
    kasan_save_stack+0x26/0x50 [Thu Feb 10 12:59:07 2022] __kasan_record_aux_stack+0xb6/0xc0 [Thu Feb 10
    12:59:07 2022] kasan_record_aux_stack_noalloc+0xb/0x10 [Thu Feb 10 12:59:07 2022] call_rcu+0x76/0x3c0 [Thu
    Feb 10 12:59:07 2022] cifs_umount+0xce/0xe0 [cifs] [Thu Feb 10 12:59:07 2022] cifs_kill_sb+0xc8/0xe0
    [cifs] [Thu Feb 10 12:59:07 2022] deactivate_locked_super+0x5d/0xd0 [Thu Feb 10 12:59:07 2022]
    cifs_smb3_do_mount+0xab9/0xbe0 [cifs] [Thu Feb 10 12:59:07 2022] smb3_get_tree+0x1a0/0x2e0 [cifs] [Thu Feb
    10 12:59:07 2022] vfs_get_tree+0x52/0x140 [Thu Feb 10 12:59:07 2022] path_mount+0x635/0x10c0 [Thu Feb 10
    12:59:07 2022] __x64_sys_mount+0x1bf/0x210 [Thu Feb 10 12:59:07 2022] do_syscall_64+0x5c/0xc0 [Thu Feb 10
    12:59:07 2022] entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2022-48919)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/05");
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
        "os_version": "8"
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
