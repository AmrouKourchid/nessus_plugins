#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231458);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-49869");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-49869");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: send: fix buffer overflow
    detection when copying path to cache entry Starting with commit c0247d289e73 (btrfs: send: annotate
    struct name_cache_entry with __counted_by()) we annotated the variable length array name from the
    name_cache_entry structure with __counted_by() to improve overflow detection. However that alone was not
    correct, because the length of that array does not match the name_len field - it matches that plus 1 to
    include the NUL string terminator, so that makes a fortified kernel think there's an overflow and report a
    splat like this: strcpy: detected buffer overflow: 20 byte write of buffer size 19 WARNING: CPU: 3 PID:
    3310 at __fortify_report+0x45/0x50 CPU: 3 UID: 0 PID: 3310 Comm: btrfs Not tainted 6.11.0-prnet #1
    Hardware name: CompuLab Ltd. sbc-ihsw/Intense-PC2 (IPC2), BIOS IPC2_3.330.7 X64 03/15/2018 RIP:
    0010:__fortify_report+0x45/0x50 Code: 48 8b 34 (...) RSP: 0018:ffff97ebc0d6f650 EFLAGS: 00010246 RAX:
    7749924ef60fa600 RBX: ffff8bf5446a521a RCX: 0000000000000027 RDX: 00000000ffffdfff RSI: ffff97ebc0d6f548
    RDI: ffff8bf84e7a1cc8 RBP: ffff8bf548574080 R08: ffffffffa8c40e10 R09: 0000000000005ffd R10:
    0000000000000004 R11: ffffffffa8c70e10 R12: ffff8bf551eef400 R13: 0000000000000000 R14: 0000000000000013
    R15: 00000000000003a8 FS: 00007fae144de8c0(0000) GS:ffff8bf84e780000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fae14691690 CR3: 00000001027a2003 CR4: 00000000001706f0
    Call Trace: <TASK> ? __warn+0x12a/0x1d0 ? __fortify_report+0x45/0x50 ? report_bug+0x154/0x1c0 ?
    handle_bug+0x42/0x70 ? exc_invalid_op+0x1a/0x50 ? asm_exc_invalid_op+0x1a/0x20 ?
    __fortify_report+0x45/0x50 __fortify_panic+0x9/0x10 __get_cur_name_and_parent+0x3bc/0x3c0
    get_cur_path+0x207/0x3b0 send_extent_data+0x709/0x10d0 ? find_parent_nodes+0x22df/0x25d0 ?
    mas_nomem+0x13/0x90 ? mtree_insert_range+0xa5/0x110 ? btrfs_lru_cache_store+0x5f/0x1e0 ?
    iterate_extent_inodes+0x52d/0x5a0 process_extent+0xa96/0x11a0 ? __pfx_lookup_backref_cache+0x10/0x10 ?
    __pfx_store_backref_cache+0x10/0x10 ? __pfx_iterate_backrefs+0x10/0x10 ? __pfx_check_extent_item+0x10/0x10
    changed_cb+0x6fa/0x930 ? tree_advance+0x362/0x390 ? memcmp_extent_buffer+0xd7/0x160
    send_subvol+0xf0a/0x1520 btrfs_ioctl_send+0x106b/0x11d0 ? __pfx___clone_root_cmp_sort+0x10/0x10
    _btrfs_ioctl_send+0x1ac/0x240 btrfs_ioctl+0x75b/0x850 __se_sys_ioctl+0xca/0x150 do_syscall_64+0x85/0x160 ?
    __count_memcg_events+0x69/0x100 ? handle_mm_fault+0x1327/0x15c0 ? __se_sys_rt_sigprocmask+0xf1/0x180 ?
    syscall_exit_to_user_mode+0x75/0xa0 ? do_syscall_64+0x91/0x160 ? do_user_addr_fault+0x21d/0x630
    entry_SYSCALL_64_after_hwframe+0x76/0x7e RIP: 0033:0x7fae145eeb4f Code: 00 48 89 (...) RSP:
    002b:00007ffdf1cb09b0 EFLAGS: 00000246 ORIG_RAX: 0000000000000010 RAX: ffffffffffffffda RBX:
    0000000000000004 RCX: 00007fae145eeb4f RDX: 00007ffdf1cb0ad0 RSI: 0000000040489426 RDI: 0000000000000004
    RBP: 00000000000078fe R08: 00007fae144006c0 R09: 00007ffdf1cb0927 R10: 0000000000000008 R11:
    0000000000000246 R12: 00007ffdf1cb1ce8 R13: 0000000000000003 R14: 000055c499fab2e0 R15: 0000000000000004
    </TASK> Fix this by not storing the NUL string terminator since we don't actually need it for name cache
    entries, this way name_len corresponds to the actual size of the name array. This requires marking the
    name array field with __nonstring and using memcpy() instead of strcpy() as recommended by the
    guidelines at: https://github.com/KSPP/linux/issues/90 (CVE-2024-49869)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49869");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
