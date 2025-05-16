#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225277);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48631");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48631");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ext4: fix bug in extents parsing when
    eh_entries == 0 and eh_depth > 0 When walking through an inode extents, the ext4_ext_binsearch_idx()
    function assumes that the extent header has been previously validated. However, there are no checks that
    verify that the number of entries (eh->eh_entries) is non-zero when depth is > 0. And this will lead to
    problems because the EXT_FIRST_INDEX() and EXT_LAST_INDEX() will return garbage and result in this: [
    135.245946] ------------[ cut here ]------------ [ 135.247579] kernel BUG at fs/ext4/extents.c:2258! [
    135.249045] invalid opcode: 0000 [#1] PREEMPT SMP [ 135.250320] CPU: 2 PID: 238 Comm: tmp118 Not tainted
    5.19.0-rc8+ #4 [ 135.252067] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
    rel-1.15.0-0-g2dd4b9b-rebuilt.opensuse.org 04/01/2014 [ 135.255065] RIP:
    0010:ext4_ext_map_blocks+0xc20/0xcb0 [ 135.256475] Code: [ 135.261433] RSP: 0018:ffffc900005939f8 EFLAGS:
    00010246 [ 135.262847] RAX: 0000000000000024 RBX: ffffc90000593b70 RCX: 0000000000000023 [ 135.264765]
    RDX: ffff8880038e5f10 RSI: 0000000000000003 RDI: ffff8880046e922c [ 135.266670] RBP: ffff8880046e9348 R08:
    0000000000000001 R09: ffff888002ca580c [ 135.268576] R10: 0000000000002602 R11: 0000000000000000 R12:
    0000000000000024 [ 135.270477] R13: 0000000000000000 R14: 0000000000000024 R15: 0000000000000000 [
    135.272394] FS: 00007fdabdc56740(0000) GS:ffff88807dd00000(0000) knlGS:0000000000000000 [ 135.274510] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 135.276075] CR2: 00007ffc26bd4f00 CR3: 0000000006261004
    CR4: 0000000000170ea0 [ 135.277952] Call Trace: [ 135.278635] <TASK> [ 135.279247] ?
    preempt_count_add+0x6d/0xa0 [ 135.280358] ? percpu_counter_add_batch+0x55/0xb0 [ 135.281612] ?
    _raw_read_unlock+0x18/0x30 [ 135.282704] ext4_map_blocks+0x294/0x5a0 [ 135.283745] ? xa_load+0x6f/0xa0 [
    135.284562] ext4_mpage_readpages+0x3d6/0x770 [ 135.285646] read_pages+0x67/0x1d0 [ 135.286492] ?
    folio_add_lru+0x51/0x80 [ 135.287441] page_cache_ra_unbounded+0x124/0x170 [ 135.288510]
    filemap_get_pages+0x23d/0x5a0 [ 135.289457] ? path_openat+0xa72/0xdd0 [ 135.290332]
    filemap_read+0xbf/0x300 [ 135.291158] ? _raw_spin_lock_irqsave+0x17/0x40 [ 135.292192]
    new_sync_read+0x103/0x170 [ 135.293014] vfs_read+0x15d/0x180 [ 135.293745] ksys_read+0xa1/0xe0 [
    135.294461] do_syscall_64+0x3c/0x80 [ 135.295284] entry_SYSCALL_64_after_hwframe+0x46/0xb0 This patch
    simply adds an extra check in __ext4_ext_check(), verifying that eh_entries is not 0 when eh_depth is > 0.
    (CVE-2022-48631)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-gcp-5.15",
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
  },
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
