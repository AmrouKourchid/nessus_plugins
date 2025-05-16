#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229284);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42317");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42317");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/huge_memory: avoid PMD-size page
    cache if needed xarray can't support arbitrary page cache size. the largest and supported page cache size
    is defined as MAX_PAGECACHE_ORDER by commit 099d90642a71 (mm/filemap: make MAX_PAGECACHE_ORDER acceptable
    to xarray). However, it's possible to have 512MB page cache in the huge memory's collapsing path on ARM64
    system whose base page size is 64KB. 512MB page cache is breaking the limitation and a warning is raised
    when the xarray entry is split as shown in the following example. [root@dhcp-10-26-1-207 ~]# cat
    /proc/1/smaps | grep KernelPageSize KernelPageSize: 64 kB [root@dhcp-10-26-1-207 ~]# cat /tmp/test.c : int
    main(int argc, char **argv) { const char *filename = TEST_XFS_FILENAME; int fd = 0; void *buf = (void
    *)-1, *p; int pgsize = getpagesize(); int ret = 0; if (pgsize != 0x10000) { fprintf(stdout, System with
    64KB base page size is required!\n); return -EPERM; } system(echo 0 >
    /sys/devices/virtual/bdi/253:0/read_ahead_kb); system(echo 1 > /proc/sys/vm/drop_caches); /* Open the
    xfs file */ fd = open(filename, O_RDONLY); assert(fd > 0); /* Create VMA */ buf = mmap(NULL,
    TEST_MEM_SIZE, PROT_READ, MAP_SHARED, fd, 0); assert(buf != (void *)-1); fprintf(stdout, mapped buffer at
    0x%p\n, buf); /* Populate VMA */ ret = madvise(buf, TEST_MEM_SIZE, MADV_NOHUGEPAGE); assert(ret == 0);
    ret = madvise(buf, TEST_MEM_SIZE, MADV_POPULATE_READ); assert(ret == 0); /* Collapse VMA */ ret =
    madvise(buf, TEST_MEM_SIZE, MADV_HUGEPAGE); assert(ret == 0); ret = madvise(buf, TEST_MEM_SIZE,
    MADV_COLLAPSE); if (ret) { fprintf(stdout, Error %d to madvise(MADV_COLLAPSE)\n, errno); goto out; } /*
    Split xarray entry. Write permission is needed */ munmap(buf, TEST_MEM_SIZE); buf = (void *)-1; close(fd);
    fd = open(filename, O_RDWR); assert(fd > 0); fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
    TEST_MEM_SIZE - pgsize, pgsize); out: if (buf != (void *)-1) munmap(buf, TEST_MEM_SIZE); if (fd > 0)
    close(fd); return ret; } [root@dhcp-10-26-1-207 ~]# gcc /tmp/test.c -o /tmp/test [root@dhcp-10-26-1-207
    ~]# /tmp/test ------------[ cut here ]------------ WARNING: CPU: 25 PID: 7560 at lib/xarray.c:1025
    xas_split_alloc+0xf8/0x128 Modules linked in: nft_fib_inet nft_fib_ipv4 nft_fib_ipv6 nft_fib \
    nft_reject_inet nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_ct \ nft_chain_nat nf_nat nf_conntrack
    nf_defrag_ipv6 nf_defrag_ipv4 \ ip_set rfkill nf_tables nfnetlink vfat fat virtio_balloon drm fuse \ xfs
    libcrc32c crct10dif_ce ghash_ce sha2_ce sha256_arm64 virtio_net \ sha1_ce net_failover virtio_blk
    virtio_console failover dimlib virtio_mmio CPU: 25 PID: 7560 Comm: test Kdump: loaded Not tainted
    6.10.0-rc7-gavin+ #9 Hardware name: QEMU KVM Virtual Machine, BIOS edk2-20240524-1.el9 05/24/2024 pstate:
    83400005 (Nzcv daif +PAN -UAO +TCO +DIT -SSBS BTYPE=--) pc : xas_split_alloc+0xf8/0x128 lr :
    split_huge_page_to_list_to_order+0x1c4/0x780 sp : ffff8000ac32f660 x29: ffff8000ac32f660 x28:
    ffff0000e0969eb0 x27: ffff8000ac32f6c0 x26: 0000000000000c40 x25: ffff0000e0969eb0 x24: 000000000000000d
    x23: ffff8000ac32f6c0 x22: ffffffdfc0700000 x21: 0000000000000000 x20: 0000000000000000 x19:
    ffffffdfc0700000 x18: 0000000000000000 x17: 0000000000000000 x16: ffffd5f3708ffc70 x15: 0000000000000000
    x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000 x11: ffffffffffffffc0 x10:
    0000000000000040 x9 : ffffd5f3708e692c x8 : 0000000000000003 x7 : 0000000000000000 x6 : ffff0000e0969eb8
    x5 : ffffd5f37289e378 x4 : 0000000000000000 x3 : 0000000000000c40 x2 : 000000000000000d x1 :
    000000000000000c x0 : 0000000000000000 Call trace: xas_split_alloc+0xf8/0x128
    split_huge_page_to_list_to_order+0x1c4/0x780 truncate_inode_partial_folio+0xdc/0x160
    truncate_inode_pages_range+0x1b4/0x4a8 truncate_pagecache_range+0x84/0xa ---truncated--- (CVE-2024-42317)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42317");

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
