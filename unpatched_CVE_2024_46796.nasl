#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229527);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46796");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46796");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: smb: client: fix double put of @cfile
    in smb2_set_path_size() If smb2_compound_op() is called with a valid @cfile and returned -EINVAL, we need
    to call cifs_get_writable_path() before retrying it as the reference of @cfile was already dropped by
    previous call. This fixes the following KASAN splat when running fstests generic/013 against Windows
    Server 2022: CIFS: Attempting to mount //w22-fs0/scratch run fstests generic/013 at 2024-09-02 19:48:59
    ================================================================== BUG: KASAN: slab-use-after-free in
    detach_if_pending+0xab/0x200 Write of size 8 at addr ffff88811f1a3730 by task kworker/3:2/176 CPU: 3 UID:
    0 PID: 176 Comm: kworker/3:2 Not tainted 6.11.0-rc6 #2 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
    BIOS 1.16.3-2.fc40 04/01/2014 Workqueue: cifsoplockd cifs_oplock_break [cifs] Call Trace: <TASK>
    dump_stack_lvl+0x5d/0x80 ? detach_if_pending+0xab/0x200 print_report+0x156/0x4d9 ?
    detach_if_pending+0xab/0x200 ? __virt_addr_valid+0x145/0x300 ? __phys_addr+0x46/0x90 ?
    detach_if_pending+0xab/0x200 kasan_report+0xda/0x110 ? detach_if_pending+0xab/0x200
    detach_if_pending+0xab/0x200 timer_delete+0x96/0xe0 ? __pfx_timer_delete+0x10/0x10 ?
    rcu_is_watching+0x20/0x50 try_to_grab_pending+0x46/0x3b0 __cancel_work+0x89/0x1b0 ?
    __pfx___cancel_work+0x10/0x10 ? kasan_save_track+0x14/0x30 cifs_close_deferred_file+0x110/0x2c0 [cifs] ?
    __pfx_cifs_close_deferred_file+0x10/0x10 [cifs] ? __pfx_down_read+0x10/0x10 cifs_oplock_break+0x4c1/0xa50
    [cifs] ? __pfx_cifs_oplock_break+0x10/0x10 [cifs] ? lock_is_held_type+0x85/0xf0 ?
    mark_held_locks+0x1a/0x90 process_one_work+0x4c6/0x9f0 ? find_held_lock+0x8a/0xa0 ?
    __pfx_process_one_work+0x10/0x10 ? lock_acquired+0x220/0x550 ? __list_add_valid_or_report+0x37/0x100
    worker_thread+0x2e4/0x570 ? __kthread_parkme+0xd1/0xf0 ? __pfx_worker_thread+0x10/0x10 kthread+0x17f/0x1c0
    ? kthread+0xda/0x1c0 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x31/0x60 ? __pfx_kthread+0x10/0x10
    ret_from_fork_asm+0x1a/0x30 </TASK> Allocated by task 1118: kasan_save_stack+0x30/0x50
    kasan_save_track+0x14/0x30 __kasan_kmalloc+0xaa/0xb0 cifs_new_fileinfo+0xc8/0x9d0 [cifs]
    cifs_atomic_open+0x467/0x770 [cifs] lookup_open.isra.0+0x665/0x8b0 path_openat+0x4c3/0x1380
    do_filp_open+0x167/0x270 do_sys_openat2+0x129/0x160 __x64_sys_creat+0xad/0xe0 do_syscall_64+0xbb/0x1d0
    entry_SYSCALL_64_after_hwframe+0x77/0x7f Freed by task 83: kasan_save_stack+0x30/0x50
    kasan_save_track+0x14/0x30 kasan_save_free_info+0x3b/0x70 poison_slab_object+0xe9/0x160
    __kasan_slab_free+0x32/0x50 kfree+0xf2/0x300 process_one_work+0x4c6/0x9f0 worker_thread+0x2e4/0x570
    kthread+0x17f/0x1c0 ret_from_fork+0x31/0x60 ret_from_fork_asm+0x1a/0x30 Last potentially related work
    creation: kasan_save_stack+0x30/0x50 __kasan_record_aux_stack+0xad/0xc0 insert_work+0x29/0xe0
    __queue_work+0x5ea/0x760 queue_work_on+0x6d/0x90 _cifsFileInfo_put+0x3f6/0x770 [cifs]
    smb2_compound_op+0x911/0x3940 [cifs] smb2_set_path_size+0x228/0x270 [cifs] cifs_set_file_size+0x197/0x460
    [cifs] cifs_setattr+0xd9c/0x14b0 [cifs] notify_change+0x4e3/0x740 do_truncate+0xfa/0x180
    vfs_truncate+0x195/0x200 __x64_sys_truncate+0x109/0x150 do_syscall_64+0xbb/0x1d0
    entry_SYSCALL_64_after_hwframe+0x77/0x7f (CVE-2024-46796)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46796");

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
