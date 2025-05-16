#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227420);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52737");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52737");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: lock the inode in shared mode
    before starting fiemap Currently fiemap does not take the inode's lock (VFS lock), it only locks a file
    range in the inode's io tree. This however can lead to a deadlock if we have a concurrent fsync on the
    file and fiemap code triggers a fault when accessing the user space buffer with fiemap_fill_next_extent().
    The deadlock happens on the inode's i_mmap_lock semaphore, which is taken both by fsync and
    btrfs_page_mkwrite(). This deadlock was recently reported by syzbot and triggers a trace like the
    following: task:syz-executor361 state:D stack:20264 pid:5668 ppid:5119 flags:0x00004004 Call Trace: <TASK>
    context_switch kernel/sched/core.c:5293 [inline] __schedule+0x995/0xe20 kernel/sched/core.c:6606
    schedule+0xcb/0x190 kernel/sched/core.c:6682 wait_on_state fs/btrfs/extent-io-tree.c:707 [inline]
    wait_extent_bit+0x577/0x6f0 fs/btrfs/extent-io-tree.c:751 lock_extent+0x1c2/0x280 fs/btrfs/extent-io-
    tree.c:1742 find_lock_delalloc_range+0x4e6/0x9c0 fs/btrfs/extent_io.c:488 writepage_delalloc+0x1ef/0x540
    fs/btrfs/extent_io.c:1863 __extent_writepage+0x736/0x14e0 fs/btrfs/extent_io.c:2174
    extent_write_cache_pages+0x983/0x1220 fs/btrfs/extent_io.c:3091 extent_writepages+0x219/0x540
    fs/btrfs/extent_io.c:3211 do_writepages+0x3c3/0x680 mm/page-writeback.c:2581
    filemap_fdatawrite_wbc+0x11e/0x170 mm/filemap.c:388 __filemap_fdatawrite_range mm/filemap.c:421 [inline]
    filemap_fdatawrite_range+0x175/0x200 mm/filemap.c:439 btrfs_fdatawrite_range fs/btrfs/file.c:3850 [inline]
    start_ordered_ops fs/btrfs/file.c:1737 [inline] btrfs_sync_file+0x4ff/0x1190 fs/btrfs/file.c:1839
    generic_write_sync include/linux/fs.h:2885 [inline] btrfs_do_write_iter+0xcd3/0x1280 fs/btrfs/file.c:1684
    call_write_iter include/linux/fs.h:2189 [inline] new_sync_write fs/read_write.c:491 [inline]
    vfs_write+0x7dc/0xc50 fs/read_write.c:584 ksys_write+0x177/0x2a0 fs/read_write.c:637 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x3d/0xb0 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x63/0xcd RIP: 0033:0x7f7d4054e9b9 RSP: 002b:00007f7d404fa2f8 EFLAGS:
    00000246 ORIG_RAX: 0000000000000001 RAX: ffffffffffffffda RBX: 00007f7d405d87a0 RCX: 00007f7d4054e9b9 RDX:
    0000000000000090 RSI: 0000000020000000 RDI: 0000000000000006 RBP: 00007f7d405a51d0 R08: 0000000000000000
    R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 61635f65646f6e69 R13:
    65646f7475616f6e R14: 7261637369646f6e R15: 00007f7d405d87a8 </TASK> INFO: task syz-executor361:5697
    blocked for more than 145 seconds. Not tainted 6.2.0-rc3-syzkaller-00376-g7c6984405241 #0 echo 0 >
    /proc/sys/kernel/hung_task_timeout_secs disables this message. task:syz-executor361 state:D stack:21216
    pid:5697 ppid:5119 flags:0x00004004 Call Trace: <TASK> context_switch kernel/sched/core.c:5293 [inline]
    __schedule+0x995/0xe20 kernel/sched/core.c:6606 schedule+0xcb/0x190 kernel/sched/core.c:6682
    rwsem_down_read_slowpath+0x5f9/0x930 kernel/locking/rwsem.c:1095 __down_read_common+0x54/0x2a0
    kernel/locking/rwsem.c:1260 btrfs_page_mkwrite+0x417/0xc80 fs/btrfs/inode.c:8526
    do_page_mkwrite+0x19e/0x5e0 mm/memory.c:2947 wp_page_shared+0x15e/0x380 mm/memory.c:3295 handle_pte_fault
    mm/memory.c:4949 [inline] __handle_mm_fault mm/memory.c:5073 [inline] handle_mm_fault+0x1b79/0x26b0
    mm/memory.c:5219 do_user_addr_fault+0x69b/0xcb0 arch/x86/mm/fault.c:1428 handle_page_fault
    arch/x86/mm/fault.c:1519 [inline] exc_page_fault+0x7a/0x110 arch/x86/mm/fault.c:1575
    asm_exc_page_fault+0x22/0x30 arch/x86/include/asm/idtentry.h:570 RIP: 0010:copy_user_short_string+0xd/0x40
    arch/x86/lib/copy_user_64.S:233 Code: 74 0a 89 (...) RSP: 0018:ffffc9000570f330 EFLAGS: 000502
    ---truncated--- (CVE-2023-52737)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
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
        "os_version": "11"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-5.15",
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-5.15",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fde-5.15",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-5.15",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-hwe-5.15",
     "linux-ibm",
     "linux-ibm-5.15",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-intel-iotg-5.15",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-lowlatency-hwe-5.15",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-5.15",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-riscv-5.15",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
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
     "linux-aws-cloud-tools-5.15.0-1004",
     "linux-aws-fips",
     "linux-aws-headers-5.15.0-1004",
     "linux-aws-tools-5.15.0-1004",
     "linux-azure-cloud-tools-5.15.0-1003",
     "linux-azure-fde",
     "linux-azure-fips",
     "linux-azure-headers-5.15.0-1003",
     "linux-azure-tools-5.15.0-1003",
     "linux-buildinfo-5.15.0-1002-gke",
     "linux-buildinfo-5.15.0-1002-ibm",
     "linux-buildinfo-5.15.0-1002-oracle",
     "linux-buildinfo-5.15.0-1003-azure",
     "linux-buildinfo-5.15.0-1003-gcp",
     "linux-buildinfo-5.15.0-1004-aws",
     "linux-buildinfo-5.15.0-1004-intel-iotg",
     "linux-buildinfo-5.15.0-1004-kvm",
     "linux-buildinfo-5.15.0-1005-raspi",
     "linux-buildinfo-5.15.0-1005-raspi-nolpae",
     "linux-buildinfo-5.15.0-24-lowlatency",
     "linux-buildinfo-5.15.0-24-lowlatency-64k",
     "linux-buildinfo-5.15.0-25-generic",
     "linux-buildinfo-5.15.0-25-generic-64k",
     "linux-cloud-tools-5.15.0-1002-ibm",
     "linux-cloud-tools-5.15.0-1002-oracle",
     "linux-cloud-tools-5.15.0-1003-azure",
     "linux-cloud-tools-5.15.0-1004-aws",
     "linux-cloud-tools-5.15.0-1004-intel-iotg",
     "linux-cloud-tools-5.15.0-1004-kvm",
     "linux-cloud-tools-5.15.0-24-lowlatency",
     "linux-cloud-tools-5.15.0-24-lowlatency-64k",
     "linux-cloud-tools-5.15.0-25",
     "linux-cloud-tools-5.15.0-25-generic",
     "linux-cloud-tools-5.15.0-25-generic-64k",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-fips",
     "linux-gcp-headers-5.15.0-1003",
     "linux-gcp-tools-5.15.0-1003",
     "linux-gke-headers-5.15.0-1002",
     "linux-gke-tools-5.15.0-1002",
     "linux-gkeop",
     "linux-headers-5.15.0-1002-gke",
     "linux-headers-5.15.0-1002-ibm",
     "linux-headers-5.15.0-1002-oracle",
     "linux-headers-5.15.0-1003-azure",
     "linux-headers-5.15.0-1003-gcp",
     "linux-headers-5.15.0-1004-aws",
     "linux-headers-5.15.0-1004-intel-iotg",
     "linux-headers-5.15.0-1004-kvm",
     "linux-headers-5.15.0-1005-raspi",
     "linux-headers-5.15.0-1005-raspi-nolpae",
     "linux-headers-5.15.0-24-lowlatency",
     "linux-headers-5.15.0-24-lowlatency-64k",
     "linux-headers-5.15.0-25",
     "linux-headers-5.15.0-25-generic",
     "linux-headers-5.15.0-25-generic-64k",
     "linux-headers-5.15.0-25-generic-lpae",
     "linux-ibm-cloud-tools-5.15.0-1002",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-5.15.0-1002",
     "linux-ibm-source-5.15.0",
     "linux-ibm-tools-5.15.0-1002",
     "linux-ibm-tools-common",
     "linux-image-5.15.0-1005-raspi",
     "linux-image-5.15.0-1005-raspi-dbgsym",
     "linux-image-5.15.0-1005-raspi-nolpae",
     "linux-image-5.15.0-1005-raspi-nolpae-dbgsym",
     "linux-image-unsigned-5.15.0-1002-gke",
     "linux-image-unsigned-5.15.0-1002-gke-dbgsym",
     "linux-image-unsigned-5.15.0-1002-ibm",
     "linux-image-unsigned-5.15.0-1002-ibm-dbgsym",
     "linux-image-unsigned-5.15.0-1002-oracle",
     "linux-image-unsigned-5.15.0-1002-oracle-dbgsym",
     "linux-image-unsigned-5.15.0-1003-azure",
     "linux-image-unsigned-5.15.0-1003-azure-dbgsym",
     "linux-image-unsigned-5.15.0-1003-gcp",
     "linux-image-unsigned-5.15.0-1003-gcp-dbgsym",
     "linux-image-unsigned-5.15.0-1004-aws",
     "linux-image-unsigned-5.15.0-1004-aws-dbgsym",
     "linux-image-unsigned-5.15.0-1004-intel-iotg",
     "linux-image-unsigned-5.15.0-1004-intel-iotg-dbgsym",
     "linux-image-unsigned-5.15.0-1004-kvm",
     "linux-image-unsigned-5.15.0-1004-kvm-dbgsym",
     "linux-image-unsigned-5.15.0-24-lowlatency",
     "linux-image-unsigned-5.15.0-24-lowlatency-64k",
     "linux-image-unsigned-5.15.0-24-lowlatency-64k-dbgsym",
     "linux-image-unsigned-5.15.0-24-lowlatency-dbgsym",
     "linux-image-unsigned-5.15.0-25-generic",
     "linux-image-unsigned-5.15.0-25-generic-64k",
     "linux-image-unsigned-5.15.0-25-generic-64k-dbgsym",
     "linux-image-unsigned-5.15.0-25-generic-dbgsym",
     "linux-image-unsigned-5.15.0-25-generic-lpae",
     "linux-intel-iot-realtime",
     "linux-intel-iotg-cloud-tools-5.15.0-1004",
     "linux-intel-iotg-cloud-tools-common",
     "linux-intel-iotg-headers-5.15.0-1004",
     "linux-intel-iotg-tools-5.15.0-1004",
     "linux-intel-iotg-tools-common",
     "linux-intel-iotg-tools-host",
     "linux-kvm-cloud-tools-5.15.0-1004",
     "linux-kvm-headers-5.15.0-1004",
     "linux-kvm-tools-5.15.0-1004",
     "linux-libc-dev",
     "linux-lowlatency-cloud-tools-5.15.0-24",
     "linux-lowlatency-cloud-tools-common",
     "linux-lowlatency-headers-5.15.0-24",
     "linux-lowlatency-tools-5.15.0-24",
     "linux-lowlatency-tools-common",
     "linux-lowlatency-tools-host",
     "linux-modules-5.15.0-1002-gke",
     "linux-modules-5.15.0-1002-ibm",
     "linux-modules-5.15.0-1002-oracle",
     "linux-modules-5.15.0-1003-azure",
     "linux-modules-5.15.0-1003-gcp",
     "linux-modules-5.15.0-1004-aws",
     "linux-modules-5.15.0-1004-intel-iotg",
     "linux-modules-5.15.0-1004-kvm",
     "linux-modules-5.15.0-1005-raspi",
     "linux-modules-5.15.0-1005-raspi-nolpae",
     "linux-modules-5.15.0-24-lowlatency",
     "linux-modules-5.15.0-24-lowlatency-64k",
     "linux-modules-5.15.0-25-generic",
     "linux-modules-5.15.0-25-generic-64k",
     "linux-modules-5.15.0-25-generic-lpae",
     "linux-modules-extra-5.15.0-1002-gke",
     "linux-modules-extra-5.15.0-1002-ibm",
     "linux-modules-extra-5.15.0-1002-oracle",
     "linux-modules-extra-5.15.0-1003-azure",
     "linux-modules-extra-5.15.0-1003-gcp",
     "linux-modules-extra-5.15.0-1004-aws",
     "linux-modules-extra-5.15.0-1004-intel-iotg",
     "linux-modules-extra-5.15.0-1004-kvm",
     "linux-modules-extra-5.15.0-1005-raspi",
     "linux-modules-extra-5.15.0-1005-raspi-nolpae",
     "linux-modules-extra-5.15.0-24-lowlatency",
     "linux-modules-extra-5.15.0-24-lowlatency-64k",
     "linux-modules-extra-5.15.0-25-generic",
     "linux-modules-extra-5.15.0-25-generic-64k",
     "linux-modules-extra-5.15.0-25-generic-lpae",
     "linux-nvidia",
     "linux-oracle-headers-5.15.0-1002",
     "linux-oracle-tools-5.15.0-1002",
     "linux-raspi-headers-5.15.0-1005",
     "linux-raspi-tools-5.15.0-1005",
     "linux-realtime",
     "linux-source-5.15.0",
     "linux-tools-5.15.0-1002-gke",
     "linux-tools-5.15.0-1002-ibm",
     "linux-tools-5.15.0-1002-oracle",
     "linux-tools-5.15.0-1003-azure",
     "linux-tools-5.15.0-1003-gcp",
     "linux-tools-5.15.0-1004-aws",
     "linux-tools-5.15.0-1004-intel-iotg",
     "linux-tools-5.15.0-1004-kvm",
     "linux-tools-5.15.0-1005-raspi",
     "linux-tools-5.15.0-1005-raspi-nolpae",
     "linux-tools-5.15.0-24-lowlatency",
     "linux-tools-5.15.0-24-lowlatency-64k",
     "linux-tools-5.15.0-25",
     "linux-tools-5.15.0-25-generic",
     "linux-tools-5.15.0-25-generic-64k",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-xilinx-zynqmp"
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
