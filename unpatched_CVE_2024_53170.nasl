#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231977);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53170");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53170");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: block: fix uaf for flush rq while
    iterating tags blk_mq_clear_flush_rq_mapping() is not called during scsi probe, by checking
    blk_queue_init_done(). However, QUEUE_FLAG_INIT_DONE is cleared in del_gendisk by commit aec89dc5d421
    (block: keep q_usage_counter in atomic mode after del_gendisk), hence for disk like scsi, following
    blk_mq_destroy_queue() will not clear flush rq from tags->rqs[] as well, cause following uaf that is found
    by our syzkaller for v6.6: ================================================================== BUG: KASAN:
    slab-use-after-free in blk_mq_find_and_get_req+0x16e/0x1a0 block/blk-mq-tag.c:261 Read of size 4 at addr
    ffff88811c969c20 by task kworker/1:2H/224909 CPU: 1 PID: 224909 Comm: kworker/1:2H Not tainted
    6.6.0-ga836a5060850 #32 Workqueue: kblockd blk_mq_timeout_work Call Trace: __dump_stack
    lib/dump_stack.c:88 [inline] dump_stack_lvl+0x91/0xf0 lib/dump_stack.c:106
    print_address_description.constprop.0+0x66/0x300 mm/kasan/report.c:364 print_report+0x3e/0x70
    mm/kasan/report.c:475 kasan_report+0xb8/0xf0 mm/kasan/report.c:588 blk_mq_find_and_get_req+0x16e/0x1a0
    block/blk-mq-tag.c:261 bt_iter block/blk-mq-tag.c:288 [inline] __sbitmap_for_each_set
    include/linux/sbitmap.h:295 [inline] sbitmap_for_each_set include/linux/sbitmap.h:316 [inline]
    bt_for_each+0x455/0x790 block/blk-mq-tag.c:325 blk_mq_queue_tag_busy_iter+0x320/0x740 block/blk-mq-
    tag.c:534 blk_mq_timeout_work+0x1a3/0x7b0 block/blk-mq.c:1673 process_one_work+0x7c4/0x1450
    kernel/workqueue.c:2631 process_scheduled_works kernel/workqueue.c:2704 [inline] worker_thread+0x804/0xe40
    kernel/workqueue.c:2785 kthread+0x346/0x450 kernel/kthread.c:388 ret_from_fork+0x4d/0x80
    arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1b/0x30 arch/x86/entry/entry_64.S:293 Allocated by task
    942: kasan_save_stack+0x22/0x50 mm/kasan/common.c:45 kasan_set_track+0x25/0x30 mm/kasan/common.c:52
    ____kasan_kmalloc mm/kasan/common.c:374 [inline] __kasan_kmalloc mm/kasan/common.c:383 [inline]
    __kasan_kmalloc+0xaa/0xb0 mm/kasan/common.c:380 kasan_kmalloc include/linux/kasan.h:198 [inline]
    __do_kmalloc_node mm/slab_common.c:1007 [inline] __kmalloc_node+0x69/0x170 mm/slab_common.c:1014
    kmalloc_node include/linux/slab.h:620 [inline] kzalloc_node include/linux/slab.h:732 [inline]
    blk_alloc_flush_queue+0x144/0x2f0 block/blk-flush.c:499 blk_mq_alloc_hctx+0x601/0x940 block/blk-mq.c:3788
    blk_mq_alloc_and_init_hctx+0x27f/0x330 block/blk-mq.c:4261 blk_mq_realloc_hw_ctxs+0x488/0x5e0 block/blk-
    mq.c:4294 blk_mq_init_allocated_queue+0x188/0x860 block/blk-mq.c:4350 blk_mq_init_queue_data block/blk-
    mq.c:4166 [inline] blk_mq_init_queue+0x8d/0x100 block/blk-mq.c:4176 scsi_alloc_sdev+0x843/0xd50
    drivers/scsi/scsi_scan.c:335 scsi_probe_and_add_lun+0x77c/0xde0 drivers/scsi/scsi_scan.c:1189
    __scsi_scan_target+0x1fc/0x5a0 drivers/scsi/scsi_scan.c:1727 scsi_scan_channel
    drivers/scsi/scsi_scan.c:1815 [inline] scsi_scan_channel+0x14b/0x1e0 drivers/scsi/scsi_scan.c:1791
    scsi_scan_host_selected+0x2fe/0x400 drivers/scsi/scsi_scan.c:1844 scsi_scan+0x3a0/0x3f0
    drivers/scsi/scsi_sysfs.c:151 store_scan+0x2a/0x60 drivers/scsi/scsi_sysfs.c:191 dev_attr_store+0x5c/0x90
    drivers/base/core.c:2388 sysfs_kf_write+0x11c/0x170 fs/sysfs/file.c:136 kernfs_fop_write_iter+0x3fc/0x610
    fs/kernfs/file.c:338 call_write_iter include/linux/fs.h:2083 [inline] new_sync_write+0x1b4/0x2d0
    fs/read_write.c:493 vfs_write+0x76c/0xb00 fs/read_write.c:586 ksys_write+0x127/0x250 fs/read_write.c:639
    do_syscall_x64 arch/x86/entry/common.c:51 [inline] do_syscall_64+0x70/0x120 arch/x86/entry/common.c:81
    entry_SYSCALL_64_after_hwframe+0x78/0xe2 Freed by task 244687: kasan_save_stack+0x22/0x50
    mm/kasan/common.c:45 kasan_set_track+0x25/0x30 mm/kasan/common.c:52 kasan_save_free_info+0x2b/0x50
    mm/kasan/generic.c:522 ____kasan_slab_free mm/kasan/common.c:236 [inline] __kasan_slab_free+0x12a/0x1b0
    mm/kasan/common.c:244 kasan_slab_free include/linux/kasan.h:164 [in ---truncated--- (CVE-2024-53170)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53170");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
    "name": [
     "linux-aws-cloud-tools-6.8.0-1008",
     "linux-aws-headers-6.8.0-1008",
     "linux-aws-tools-6.8.0-1008",
     "linux-azure-cloud-tools-6.8.0-1007",
     "linux-azure-headers-6.8.0-1007",
     "linux-azure-tools-6.8.0-1007",
     "linux-buildinfo-6.8.0-1003-gke",
     "linux-buildinfo-6.8.0-1004-raspi",
     "linux-buildinfo-6.8.0-1005-ibm",
     "linux-buildinfo-6.8.0-1005-oem",
     "linux-buildinfo-6.8.0-1005-oracle",
     "linux-buildinfo-6.8.0-1005-oracle-64k",
     "linux-buildinfo-6.8.0-1007-azure",
     "linux-buildinfo-6.8.0-1007-gcp",
     "linux-buildinfo-6.8.0-1008-aws",
     "linux-buildinfo-6.8.0-31-generic",
     "linux-buildinfo-6.8.0-31-generic-64k",
     "linux-buildinfo-6.8.0-31-lowlatency",
     "linux-cloud-tools-6.8.0-1005-ibm",
     "linux-cloud-tools-6.8.0-1005-oem",
     "linux-cloud-tools-6.8.0-1005-oracle",
     "linux-cloud-tools-6.8.0-1005-oracle-64k",
     "linux-cloud-tools-6.8.0-1007-azure",
     "linux-cloud-tools-6.8.0-1008-aws",
     "linux-cloud-tools-6.8.0-31",
     "linux-cloud-tools-6.8.0-31-generic",
     "linux-cloud-tools-6.8.0-31-generic-64k",
     "linux-cloud-tools-6.8.0-31-lowlatency",
     "linux-cloud-tools-6.8.0-31-lowlatency-64k",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-headers-6.8.0-1007",
     "linux-gcp-tools-6.8.0-1007",
     "linux-gke-headers-6.8.0-1003",
     "linux-gke-tools-6.8.0-1003",
     "linux-gkeop",
     "linux-headers-6.8.0-1003-gke",
     "linux-headers-6.8.0-1004-raspi",
     "linux-headers-6.8.0-1005-ibm",
     "linux-headers-6.8.0-1005-oem",
     "linux-headers-6.8.0-1005-oracle",
     "linux-headers-6.8.0-1005-oracle-64k",
     "linux-headers-6.8.0-1007-azure",
     "linux-headers-6.8.0-1007-gcp",
     "linux-headers-6.8.0-1008-aws",
     "linux-headers-6.8.0-31",
     "linux-headers-6.8.0-31-generic",
     "linux-headers-6.8.0-31-generic-64k",
     "linux-headers-6.8.0-31-lowlatency",
     "linux-headers-6.8.0-31-lowlatency-64k",
     "linux-ibm-cloud-tools-6.8.0-1005",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-6.8.0-1005",
     "linux-ibm-source-6.8.0",
     "linux-ibm-tools-6.8.0-1005",
     "linux-ibm-tools-common",
     "linux-image-6.8.0-1004-raspi",
     "linux-image-6.8.0-1004-raspi-dbgsym",
     "linux-image-6.8.0-31-generic",
     "linux-image-6.8.0-31-generic-dbgsym",
     "linux-image-unsigned-6.8.0-1003-gke",
     "linux-image-unsigned-6.8.0-1003-gke-dbgsym",
     "linux-image-unsigned-6.8.0-1005-ibm",
     "linux-image-unsigned-6.8.0-1005-ibm-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oem",
     "linux-image-unsigned-6.8.0-1005-oem-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oracle",
     "linux-image-unsigned-6.8.0-1005-oracle-64k",
     "linux-image-unsigned-6.8.0-1005-oracle-64k-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oracle-dbgsym",
     "linux-image-unsigned-6.8.0-1007-azure",
     "linux-image-unsigned-6.8.0-1007-azure-dbgsym",
     "linux-image-unsigned-6.8.0-1007-gcp",
     "linux-image-unsigned-6.8.0-1007-gcp-dbgsym",
     "linux-image-unsigned-6.8.0-1008-aws",
     "linux-image-unsigned-6.8.0-1008-aws-dbgsym",
     "linux-image-unsigned-6.8.0-31-generic",
     "linux-image-unsigned-6.8.0-31-generic-64k",
     "linux-image-unsigned-6.8.0-31-generic-64k-dbgsym",
     "linux-image-unsigned-6.8.0-31-generic-dbgsym",
     "linux-image-unsigned-6.8.0-31-lowlatency",
     "linux-image-unsigned-6.8.0-31-lowlatency-64k",
     "linux-image-unsigned-6.8.0-31-lowlatency-64k-dbgsym",
     "linux-image-unsigned-6.8.0-31-lowlatency-dbgsym",
     "linux-intel",
     "linux-lib-rust-6.8.0-31-generic",
     "linux-lib-rust-6.8.0-31-generic-64k",
     "linux-libc-dev",
     "linux-lowlatency-cloud-tools-6.8.0-31",
     "linux-lowlatency-cloud-tools-common",
     "linux-lowlatency-headers-6.8.0-31",
     "linux-lowlatency-hwe-6.11",
     "linux-lowlatency-lib-rust-6.8.0-31-lowlatency",
     "linux-lowlatency-lib-rust-6.8.0-31-lowlatency-64k",
     "linux-lowlatency-tools-6.8.0-31",
     "linux-lowlatency-tools-common",
     "linux-lowlatency-tools-host",
     "linux-modules-6.8.0-1003-gke",
     "linux-modules-6.8.0-1004-raspi",
     "linux-modules-6.8.0-1005-ibm",
     "linux-modules-6.8.0-1005-oem",
     "linux-modules-6.8.0-1005-oracle",
     "linux-modules-6.8.0-1005-oracle-64k",
     "linux-modules-6.8.0-1007-azure",
     "linux-modules-6.8.0-1007-gcp",
     "linux-modules-6.8.0-1008-aws",
     "linux-modules-6.8.0-31-generic",
     "linux-modules-6.8.0-31-generic-64k",
     "linux-modules-6.8.0-31-lowlatency",
     "linux-modules-6.8.0-31-lowlatency-64k",
     "linux-modules-extra-6.8.0-1003-gke",
     "linux-modules-extra-6.8.0-1005-ibm",
     "linux-modules-extra-6.8.0-1005-oem",
     "linux-modules-extra-6.8.0-1005-oracle",
     "linux-modules-extra-6.8.0-1005-oracle-64k",
     "linux-modules-extra-6.8.0-1007-azure",
     "linux-modules-extra-6.8.0-1007-gcp",
     "linux-modules-extra-6.8.0-1008-aws",
     "linux-modules-extra-6.8.0-31-generic",
     "linux-modules-extra-6.8.0-31-generic-64k",
     "linux-modules-extra-6.8.0-31-lowlatency",
     "linux-modules-extra-6.8.0-31-lowlatency-64k",
     "linux-modules-ipu6-6.8.0-1005-oem",
     "linux-modules-ipu6-6.8.0-31-generic",
     "linux-modules-ivsc-6.8.0-31-generic",
     "linux-modules-iwlwifi-6.8.0-1004-raspi",
     "linux-modules-iwlwifi-6.8.0-1005-ibm",
     "linux-modules-iwlwifi-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1005-oracle",
     "linux-modules-iwlwifi-6.8.0-1005-oracle-64k",
     "linux-modules-iwlwifi-6.8.0-1007-azure",
     "linux-modules-iwlwifi-6.8.0-1007-gcp",
     "linux-modules-iwlwifi-6.8.0-31-generic",
     "linux-modules-iwlwifi-6.8.0-31-lowlatency",
     "linux-nvidia",
     "linux-nvidia-lowlatency",
     "linux-oem-6.8-headers-6.8.0-1005",
     "linux-oem-6.8-lib-rust-6.8.0-1005-oem",
     "linux-oem-6.8-tools-6.8.0-1005",
     "linux-oracle-headers-6.8.0-1005",
     "linux-oracle-tools-6.8.0-1005",
     "linux-raspi-headers-6.8.0-1004",
     "linux-raspi-realtime",
     "linux-raspi-tools-6.8.0-1004",
     "linux-realtime",
     "linux-riscv-headers-6.8.0-31",
     "linux-riscv-tools-6.8.0-31",
     "linux-source-6.8.0",
     "linux-tools-6.8.0-1003-gke",
     "linux-tools-6.8.0-1004-raspi",
     "linux-tools-6.8.0-1005-ibm",
     "linux-tools-6.8.0-1005-oem",
     "linux-tools-6.8.0-1005-oracle",
     "linux-tools-6.8.0-1005-oracle-64k",
     "linux-tools-6.8.0-1007-azure",
     "linux-tools-6.8.0-1007-gcp",
     "linux-tools-6.8.0-1008-aws",
     "linux-tools-6.8.0-31",
     "linux-tools-6.8.0-31-generic",
     "linux-tools-6.8.0-31-generic-64k",
     "linux-tools-6.8.0-31-lowlatency",
     "linux-tools-6.8.0-31-lowlatency-64k",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure"
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
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-6.8",
     "linux-azure-6.8",
     "linux-gcp-6.8",
     "linux-hwe-6.8",
     "linux-lowlatency-hwe-6.8",
     "linux-nvidia-6.8",
     "linux-oracle-6.8",
     "linux-riscv-6.8"
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
