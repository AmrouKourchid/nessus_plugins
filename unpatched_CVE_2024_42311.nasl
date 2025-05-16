#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228376);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42311");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42311");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: hfs: fix to initialize fields of
    hfs_inode_info after hfs_alloc_inode() Syzbot reports uninitialized value access issue as below: loop0:
    detected capacity change from 0 to 64 ===================================================== BUG: KMSAN:
    uninit-value in hfs_revalidate_dentry+0x307/0x3f0 fs/hfs/sysdep.c:30 hfs_revalidate_dentry+0x307/0x3f0
    fs/hfs/sysdep.c:30 d_revalidate fs/namei.c:862 [inline] lookup_fast+0x89e/0x8e0 fs/namei.c:1649
    walk_component fs/namei.c:2001 [inline] link_path_walk+0x817/0x1480 fs/namei.c:2332
    path_lookupat+0xd9/0x6f0 fs/namei.c:2485 filename_lookup+0x22e/0x740 fs/namei.c:2515
    user_path_at_empty+0x8b/0x390 fs/namei.c:2924 user_path_at include/linux/namei.h:57 [inline] do_mount
    fs/namespace.c:3689 [inline] __do_sys_mount fs/namespace.c:3898 [inline] __se_sys_mount+0x66b/0x810
    fs/namespace.c:3875 __x64_sys_mount+0xe4/0x140 fs/namespace.c:3875 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b BUG: KMSAN: uninit-value in hfs_ext_read_extent
    fs/hfs/extent.c:196 [inline] BUG: KMSAN: uninit-value in hfs_get_block+0x92d/0x1620 fs/hfs/extent.c:366
    hfs_ext_read_extent fs/hfs/extent.c:196 [inline] hfs_get_block+0x92d/0x1620 fs/hfs/extent.c:366
    block_read_full_folio+0x4ff/0x11b0 fs/buffer.c:2271 hfs_read_folio+0x55/0x60 fs/hfs/inode.c:39
    filemap_read_folio+0x148/0x4f0 mm/filemap.c:2426 do_read_cache_folio+0x7c8/0xd90 mm/filemap.c:3553
    do_read_cache_page mm/filemap.c:3595 [inline] read_cache_page+0xfb/0x2f0 mm/filemap.c:3604
    read_mapping_page include/linux/pagemap.h:755 [inline] hfs_btree_open+0x928/0x1ae0 fs/hfs/btree.c:78
    hfs_mdb_get+0x260c/0x3000 fs/hfs/mdb.c:204 hfs_fill_super+0x1fb1/0x2790 fs/hfs/super.c:406
    mount_bdev+0x628/0x920 fs/super.c:1359 hfs_mount+0xcd/0xe0 fs/hfs/super.c:456 legacy_get_tree+0x167/0x2e0
    fs/fs_context.c:610 vfs_get_tree+0xdc/0x5d0 fs/super.c:1489 do_new_mount+0x7a9/0x16f0 fs/namespace.c:3145
    path_mount+0xf98/0x26a0 fs/namespace.c:3475 do_mount fs/namespace.c:3488 [inline] __do_sys_mount
    fs/namespace.c:3697 [inline] __se_sys_mount+0x919/0x9e0 fs/namespace.c:3674 __ia32_sys_mount+0x15b/0x1b0
    fs/namespace.c:3674 do_syscall_32_irqs_on arch/x86/entry/common.c:112 [inline]
    __do_fast_syscall_32+0xa2/0x100 arch/x86/entry/common.c:178 do_fast_syscall_32+0x37/0x80
    arch/x86/entry/common.c:203 do_SYSENTER_32+0x1f/0x30 arch/x86/entry/common.c:246
    entry_SYSENTER_compat_after_hwframe+0x70/0x82 Uninit was created at: __alloc_pages+0x9a6/0xe00
    mm/page_alloc.c:4590 __alloc_pages_node include/linux/gfp.h:238 [inline] alloc_pages_node
    include/linux/gfp.h:261 [inline] alloc_slab_page mm/slub.c:2190 [inline] allocate_slab mm/slub.c:2354
    [inline] new_slab+0x2d7/0x1400 mm/slub.c:2407 ___slab_alloc+0x16b5/0x3970 mm/slub.c:3540 __slab_alloc
    mm/slub.c:3625 [inline] __slab_alloc_node mm/slub.c:3678 [inline] slab_alloc_node mm/slub.c:3850 [inline]
    kmem_cache_alloc_lru+0x64d/0xb30 mm/slub.c:3879 alloc_inode_sb include/linux/fs.h:3018 [inline]
    hfs_alloc_inode+0x5a/0xc0 fs/hfs/super.c:165 alloc_inode+0x83/0x440 fs/inode.c:260 new_inode_pseudo
    fs/inode.c:1005 [inline] new_inode+0x38/0x4f0 fs/inode.c:1031 hfs_new_inode+0x61/0x1010 fs/hfs/inode.c:186
    hfs_mkdir+0x54/0x250 fs/hfs/dir.c:228 vfs_mkdir+0x49a/0x700 fs/namei.c:4126 do_mkdirat+0x529/0x810
    fs/namei.c:4149 __do_sys_mkdirat fs/namei.c:4164 [inline] __se_sys_mkdirat fs/namei.c:4162 [inline]
    __x64_sys_mkdirat+0xc8/0x120 fs/namei.c:4162 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b It missed to
    initialize .tz_secondswest, .cached_start and .cached_blocks fields in struct hfs_inode_info after
    hfs_alloc_inode(), fix it. (CVE-2024-42311)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42311");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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
    "name": "linux-azure-fde",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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
        "os_version": "20.04"
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
