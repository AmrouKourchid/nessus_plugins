#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228979);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42241");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42241");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/shmem: disable PMD-sized page cache
    if needed For shmem files, it's possible that PMD-sized page cache can't be supported by xarray. For
    example, 512MB page cache on ARM64 when the base page size is 64KB can't be supported by xarray. It leads
    to errors as the following messages indicate when this sort of xarray entry is split. WARNING: CPU: 34
    PID: 7578 at lib/xarray.c:1025 xas_split_alloc+0xf8/0x128 Modules linked in: binfmt_misc nft_fib_inet
    nft_fib_ipv4 nft_fib_ipv6 \ nft_fib nft_reject_inet nf_reject_ipv4 nf_reject_ipv6 nft_reject \ nft_ct
    nft_chain_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 \ ip_set rfkill nf_tables nfnetlink vfat
    fat virtio_balloon drm fuse xfs \ libcrc32c crct10dif_ce ghash_ce sha2_ce sha256_arm64 sha1_ce virtio_net
    \ net_failover virtio_console virtio_blk failover dimlib virtio_mmio CPU: 34 PID: 7578 Comm: test Kdump:
    loaded Tainted: G W 6.10.0-rc5-gavin+ #9 Hardware name: QEMU KVM Virtual Machine, BIOS edk2-20240524-1.el9
    05/24/2024 pstate: 83400005 (Nzcv daif +PAN -UAO +TCO +DIT -SSBS BTYPE=--) pc : xas_split_alloc+0xf8/0x128
    lr : split_huge_page_to_list_to_order+0x1c4/0x720 sp : ffff8000882af5f0 x29: ffff8000882af5f0 x28:
    ffff8000882af650 x27: ffff8000882af768 x26: 0000000000000cc0 x25: 000000000000000d x24: ffff00010625b858
    x23: ffff8000882af650 x22: ffffffdfc0900000 x21: 0000000000000000 x20: 0000000000000000 x19:
    ffffffdfc0900000 x18: 0000000000000000 x17: 0000000000000000 x16: 0000018000000000 x15: 52f8004000000000
    x14: 0000e00000000000 x13: 0000000000002000 x12: 0000000000000020 x11: 52f8000000000000 x10:
    52f8e1c0ffff6000 x9 : ffffbeb9619a681c x8 : 0000000000000003 x7 : 0000000000000000 x6 : ffff00010b02ddb0
    x5 : ffffbeb96395e378 x4 : 0000000000000000 x3 : 0000000000000cc0 x2 : 000000000000000d x1 :
    000000000000000c x0 : 0000000000000000 Call trace: xas_split_alloc+0xf8/0x128
    split_huge_page_to_list_to_order+0x1c4/0x720 truncate_inode_partial_folio+0xdc/0x160
    shmem_undo_range+0x2bc/0x6a8 shmem_fallocate+0x134/0x430 vfs_fallocate+0x124/0x2e8
    ksys_fallocate+0x4c/0xa0 __arm64_sys_fallocate+0x24/0x38 invoke_syscall.constprop.0+0x7c/0xd8
    do_el0_svc+0xb4/0xd0 el0_svc+0x44/0x1d8 el0t_64_sync_handler+0x134/0x150 el0t_64_sync+0x17c/0x180 Fix it
    by disabling PMD-sized page cache when HPAGE_PMD_ORDER is larger than MAX_PAGECACHE_ORDER. As Matthew
    Wilcox pointed, the page cache in a shmem file isn't represented by a multi-index entry and doesn't have
    this limitation when the xarry entry is split until commit 6b24ca4a1a8d (mm: Use multi-index entries in
    the page cache). (CVE-2024-42241)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42241");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "btrfs-modules-6.1.0-29-alpha-generic-di",
     "cdrom-core-modules-6.1.0-29-alpha-generic-di",
     "ext4-modules-6.1.0-29-alpha-generic-di",
     "fat-modules-6.1.0-29-alpha-generic-di",
     "isofs-modules-6.1.0-29-alpha-generic-di",
     "jfs-modules-6.1.0-29-alpha-generic-di",
     "kernel-image-6.1.0-29-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-29-common",
     "linux-headers-6.1.0-29-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-29",
     "loop-modules-6.1.0-29-alpha-generic-di",
     "nic-modules-6.1.0-29-alpha-generic-di",
     "nic-shared-modules-6.1.0-29-alpha-generic-di",
     "nic-wireless-modules-6.1.0-29-alpha-generic-di",
     "pata-modules-6.1.0-29-alpha-generic-di",
     "ppp-modules-6.1.0-29-alpha-generic-di",
     "scsi-core-modules-6.1.0-29-alpha-generic-di",
     "scsi-modules-6.1.0-29-alpha-generic-di",
     "scsi-nic-modules-6.1.0-29-alpha-generic-di",
     "serial-modules-6.1.0-29-alpha-generic-di",
     "usb-serial-modules-6.1.0-29-alpha-generic-di",
     "xfs-modules-6.1.0-29-alpha-generic-di"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "12"
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
