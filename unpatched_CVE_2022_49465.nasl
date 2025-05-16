#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226209);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49465");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49465");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: blk-throttle: Set BIO_THROTTLED when
    bio has been throttled 1.In current process, all bio will set the BIO_THROTTLED flag after
    __blk_throtl_bio(). 2.If bio needs to be throttled, it will start the timer and stop submit bio directly.
    Bio will submit in blk_throtl_dispatch_work_fn() when the timer expires.But in the current process, if bio
    is throttled. The BIO_THROTTLED will be set to bio after timer start. If the bio has been completed, it
    may cause use-after-free blow. BUG: KASAN: use-after-free in blk_throtl_bio+0x12f0/0x2c70 Read of size 2
    at addr ffff88801b8902d4 by task fio/26380 dump_stack+0x9b/0xce
    print_address_description.constprop.6+0x3e/0x60 kasan_report.cold.9+0x22/0x3a blk_throtl_bio+0x12f0/0x2c70
    submit_bio_checks+0x701/0x1550 submit_bio_noacct+0x83/0xc80 submit_bio+0xa7/0x330
    mpage_readahead+0x380/0x500 read_pages+0x1c1/0xbf0 page_cache_ra_unbounded+0x471/0x6f0
    do_page_cache_ra+0xda/0x110 ondemand_readahead+0x442/0xae0 page_cache_async_ra+0x210/0x300
    generic_file_buffered_read+0x4d9/0x2130 generic_file_read_iter+0x315/0x490 blkdev_read_iter+0x113/0x1b0
    aio_read+0x2ad/0x450 io_submit_one+0xc8e/0x1d60 __se_sys_io_submit+0x125/0x350 do_syscall_64+0x2d/0x40
    entry_SYSCALL_64_after_hwframe+0x44/0xa9 Allocated by task 26380: kasan_save_stack+0x19/0x40
    __kasan_kmalloc.constprop.2+0xc1/0xd0 kmem_cache_alloc+0x146/0x440 mempool_alloc+0x125/0x2f0
    bio_alloc_bioset+0x353/0x590 mpage_alloc+0x3b/0x240 do_mpage_readpage+0xddf/0x1ef0
    mpage_readahead+0x264/0x500 read_pages+0x1c1/0xbf0 page_cache_ra_unbounded+0x471/0x6f0
    do_page_cache_ra+0xda/0x110 ondemand_readahead+0x442/0xae0 page_cache_async_ra+0x210/0x300
    generic_file_buffered_read+0x4d9/0x2130 generic_file_read_iter+0x315/0x490 blkdev_read_iter+0x113/0x1b0
    aio_read+0x2ad/0x450 io_submit_one+0xc8e/0x1d60 __se_sys_io_submit+0x125/0x350 do_syscall_64+0x2d/0x40
    entry_SYSCALL_64_after_hwframe+0x44/0xa9 Freed by task 0: kasan_save_stack+0x19/0x40
    kasan_set_track+0x1c/0x30 kasan_set_free_info+0x1b/0x30 __kasan_slab_free+0x111/0x160
    kmem_cache_free+0x94/0x460 mempool_free+0xd6/0x320 bio_free+0xe0/0x130 bio_put+0xab/0xe0
    bio_endio+0x3a6/0x5d0 blk_update_request+0x590/0x1370 scsi_end_request+0x7d/0x400
    scsi_io_completion+0x1aa/0xe50 scsi_softirq_done+0x11b/0x240 blk_mq_complete_request+0xd4/0x120
    scsi_mq_done+0xf0/0x200 virtscsi_vq_done+0xbc/0x150 vring_interrupt+0x179/0x390
    __handle_irq_event_percpu+0xf7/0x490 handle_irq_event_percpu+0x7b/0x160 handle_irq_event+0xcc/0x170
    handle_edge_irq+0x215/0xb20 common_interrupt+0x60/0x120 asm_common_interrupt+0x1e/0x40 Fix this by move
    BIO_THROTTLED set into the queue_lock. (CVE-2022-49465)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
