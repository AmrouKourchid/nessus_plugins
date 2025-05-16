#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229329);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42243");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42243");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/filemap: make MAX_PAGECACHE_ORDER
    acceptable to xarray Patch series mm/filemap: Limit page cache size to that supported by xarray, v2.
    Currently, xarray can't support arbitrary page cache size. More details can be found from the WARN_ON()
    statement in xas_split_alloc(). In our test whose code is attached below, we hit the WARN_ON() on ARM64
    system where the base page size is 64KB and huge page size is 512MB. The issue was reported long time ago
    and some discussions on it can be found here [1]. [1] https://www.spinics.net/lists/linux-
    xfs/msg75404.html In order to fix the issue, we need to adjust MAX_PAGECACHE_ORDER to one supported by
    xarray and avoid PMD-sized page cache if needed. The code changes are suggested by David Hildenbrand.
    PATCH[1] adjusts MAX_PAGECACHE_ORDER to that supported by xarray PATCH[2-3] avoids PMD-sized page cache in
    the synchronous readahead path PATCH[4] avoids PMD-sized page cache for shmem files if needed Test program
    ============ # cat test.c #define _GNU_SOURCE #include <stdio.h> #include <stdlib.h> #include <unistd.h>
    #include <string.h> #include <fcntl.h> #include <errno.h> #include <sys/syscall.h> #include <sys/mman.h>
    #define TEST_XFS_FILENAME /tmp/data #define TEST_SHMEM_FILENAME /dev/shm/data #define TEST_MEM_SIZE
    0x20000000 int main(int argc, char **argv) { const char *filename; int fd = 0; void *buf = (void *)-1, *p;
    int pgsize = getpagesize(); int ret; if (pgsize != 0x10000) { fprintf(stderr, 64KB base page size is
    required\n); return -EPERM; } system(echo force > /sys/kernel/mm/transparent_hugepage/shmem_enabled);
    system(rm -fr /tmp/data); system(rm -fr /dev/shm/data); system(echo 1 > /proc/sys/vm/drop_caches);
    /* Open xfs or shmem file */ filename = TEST_XFS_FILENAME; if (argc > 1 && !strcmp(argv[1], shmem))
    filename = TEST_SHMEM_FILENAME; fd = open(filename, O_CREAT | O_RDWR | O_TRUNC); if (fd < 0) {
    fprintf(stderr, Unable to open <%s>\n, filename); return -EIO; } /* Extend file size */ ret =
    ftruncate(fd, TEST_MEM_SIZE); if (ret) { fprintf(stderr, Error %d to ftruncate()\n, ret); goto cleanup;
    } /* Create VMA */ buf = mmap(NULL, TEST_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); if (buf ==
    (void *)-1) { fprintf(stderr, Unable to mmap <%s>\n, filename); goto cleanup; } fprintf(stdout, mapped
    buffer at 0x%p\n, buf); ret = madvise(buf, TEST_MEM_SIZE, MADV_HUGEPAGE); if (ret) { fprintf(stderr,
    Unable to madvise(MADV_HUGEPAGE)\n); goto cleanup; } /* Populate VMA */ ret = madvise(buf,
    TEST_MEM_SIZE, MADV_POPULATE_WRITE); if (ret) { fprintf(stderr, Error %d to
    madvise(MADV_POPULATE_WRITE)\n, ret); goto cleanup; } /* Punch the file to enforce xarray split */ ret =
    fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, TEST_MEM_SIZE - pgsize, pgsize); if (ret)
    fprintf(stderr, Error %d to fallocate()\n, ret); cleanup: if (buf != (void *)-1) munmap(buf,
    TEST_MEM_SIZE); if (fd > 0) close(fd); return 0; } # gcc test.c -o test # cat /proc/1/smaps | grep
    KernelPageSize | head -n 1 KernelPageSize: 64 kB # ./test shmem : ------------[ cut here ]------------
    WARNING: CPU: 17 PID: 5253 at lib/xarray.c:1025 xas_split_alloc+0xf8/0x128 Modules linked in: nft_fib_inet
    nft_fib_ipv4 nft_fib_ipv6 nft_fib \ nft_reject_inet nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_ct \
    nft_chain_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 \ ip_set nf_tables rfkill nfnetlink vfat
    fat virtio_balloon \ drm fuse xfs libcrc32c crct10dif_ce ghash_ce sha2_ce sha256_arm64 \ virtio_net
    sha1_ce net_failover failover virtio_console virtio_blk \ dimlib virtio_mmio CPU: 17 PID: 5253 Comm: test
    Kdump: loaded Tainted: G W 6.10.0-rc5-gavin+ #12 Hardware name: QEMU KVM Virtual Machine, BIOS
    edk2-20240524-1.el9 05/24/2024 pstate: 83400005 (Nzcv daif +PAN -UAO +TC ---truncated--- (CVE-2024-42243)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42243");

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
