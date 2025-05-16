#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230151);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46987");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46987");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: fix deadlock when cloning
    inline extents and using qgroups There are a few exceptional cases where cloning an inline extent needs to
    copy the inline extent data into a page of the destination inode. When this happens, we end up starting a
    transaction while having a dirty page for the destination inode and while having the range locked in the
    destination's inode iotree too. Because when reserving metadata space for a transaction we may need to
    flush existing delalloc in case there is not enough free space, we have a mechanism in place to prevent a
    deadlock, which was introduced in commit 3d45f221ce627d (btrfs: fix deadlock when cloning inline extent
    and low on free metadata space). However when using qgroups, a transaction also reserves metadata qgroup
    space, which can also result in flushing delalloc in case there is not enough available space at the
    moment. When this happens we deadlock, since flushing delalloc requires locking the file range in the
    inode's iotree and the range was already locked at the very beginning of the clone operation, before
    attempting to start the transaction. When this issue happens, stack traces like the following are
    reported: [72747.556262] task:kworker/u81:9 state:D stack: 0 pid: 225 ppid: 2 flags:0x00004000
    [72747.556268] Workqueue: writeback wb_workfn (flush-btrfs-1142) [72747.556271] Call Trace: [72747.556273]
    __schedule+0x296/0x760 [72747.556277] schedule+0x3c/0xa0 [72747.556279] io_schedule+0x12/0x40
    [72747.556284] __lock_page+0x13c/0x280 [72747.556287] ? generic_file_readonly_mmap+0x70/0x70
    [72747.556325] extent_write_cache_pages+0x22a/0x440 [btrfs] [72747.556331] ?
    __set_page_dirty_nobuffers+0xe7/0x160 [72747.556358] ? set_extent_buffer_dirty+0x5e/0x80 [btrfs]
    [72747.556362] ? update_group_capacity+0x25/0x210 [72747.556366] ? cpumask_next_and+0x1a/0x20
    [72747.556391] extent_writepages+0x44/0xa0 [btrfs] [72747.556394] do_writepages+0x41/0xd0 [72747.556398]
    __writeback_single_inode+0x39/0x2a0 [72747.556403] writeback_sb_inodes+0x1ea/0x440 [72747.556407]
    __writeback_inodes_wb+0x5f/0xc0 [72747.556410] wb_writeback+0x235/0x2b0 [72747.556414] ?
    get_nr_inodes+0x35/0x50 [72747.556417] wb_workfn+0x354/0x490 [72747.556420] ? newidle_balance+0x2c5/0x3e0
    [72747.556424] process_one_work+0x1aa/0x340 [72747.556426] worker_thread+0x30/0x390 [72747.556429] ?
    create_worker+0x1a0/0x1a0 [72747.556432] kthread+0x116/0x130 [72747.556435] ? kthread_park+0x80/0x80
    [72747.556438] ret_from_fork+0x1f/0x30 [72747.566958] Workqueue: btrfs-flush_delalloc btrfs_work_helper
    [btrfs] [72747.566961] Call Trace: [72747.566964] __schedule+0x296/0x760 [72747.566968] ?
    finish_wait+0x80/0x80 [72747.566970] schedule+0x3c/0xa0 [72747.566995]
    wait_extent_bit.constprop.68+0x13b/0x1c0 [btrfs] [72747.566999] ? finish_wait+0x80/0x80 [72747.567024]
    lock_extent_bits+0x37/0x90 [btrfs] [72747.567047] btrfs_invalidatepage+0x299/0x2c0 [btrfs] [72747.567051]
    ? find_get_pages_range_tag+0x2cd/0x380 [72747.567076] __extent_writepage+0x203/0x320 [btrfs]
    [72747.567102] extent_write_cache_pages+0x2bb/0x440 [btrfs] [72747.567106] ? update_load_avg+0x7e/0x5f0
    [72747.567109] ? enqueue_entity+0xf4/0x6f0 [72747.567134] extent_writepages+0x44/0xa0 [btrfs]
    [72747.567137] ? enqueue_task_fair+0x93/0x6f0 [72747.567140] do_writepages+0x41/0xd0 [72747.567144]
    __filemap_fdatawrite_range+0xc7/0x100 [72747.567167] btrfs_run_delalloc_work+0x17/0x40 [btrfs]
    [72747.567195] btrfs_work_helper+0xc2/0x300 [btrfs] [72747.567200] process_one_work+0x1aa/0x340
    [72747.567202] worker_thread+0x30/0x390 [72747.567205] ? create_worker+0x1a0/0x1a0 [72747.567208]
    kthread+0x116/0x130 [72747.567211] ? kthread_park+0x80/0x80 [72747.567214] ret_from_fork+0x1f/0x30
    [72747.569686] task:fsstress state:D stack: ---truncated--- (CVE-2021-46987)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46987");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
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
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
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
     "linux-ibm",
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
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
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
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
