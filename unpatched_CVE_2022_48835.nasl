#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225240);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48835");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48835");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: mpt3sas: Page fault in reply q
    processing A page fault was encountered in mpt3sas on a LUN reset error path: [ 145.763216] mpt3sas_cm1:
    Task abort tm failed: handle(0x0002),timeout(30) tr_method(0x0) smid(3) msix_index(0) [ 145.778932] scsi
    1:0:0:0: task abort: FAILED scmd(0x0000000024ba29a2) [ 145.817307] scsi 1:0:0:0: attempting device reset!
    scmd(0x0000000024ba29a2) [ 145.827253] scsi 1:0:0:0: [sg1] tag#2 CDB: Receive Diagnostic 1c 01 01 ff fc 00
    [ 145.837617] scsi target1:0:0: handle(0x0002), sas_address(0x500605b0000272b9), phy(0) [ 145.848598] scsi
    target1:0:0: enclosure logical id(0x500605b0000272b8), slot(0) [ 149.858378] mpt3sas_cm1: Poll
    ReplyDescriptor queues for completion of smid(0), task_type(0x05), handle(0x0002) [ 149.875202] BUG:
    unable to handle page fault for address: 00000007fffc445d [ 149.885617] #PF: supervisor read access in
    kernel mode [ 149.894346] #PF: error_code(0x0000) - not-present page [ 149.903123] PGD 0 P4D 0 [
    149.909387] Oops: 0000 [#1] PREEMPT SMP NOPTI [ 149.917417] CPU: 24 PID: 3512 Comm: scsi_eh_1 Kdump:
    loaded Tainted: G S O 5.10.89-altav-1 #1 [ 149.934327] Hardware name: DDN 200NVX2 /200NVX2-MB , BIOS
    ATHG2.2.02.01 09/10/2021 [ 149.951871] RIP: 0010:_base_process_reply_queue+0x4b/0x900 [mpt3sas] [
    149.961889] Code: 0f 84 22 02 00 00 8d 48 01 49 89 fd 48 8d 57 38 f0 0f b1 4f 38 0f 85 d8 01 00 00 49 8b
    45 10 45 31 e4 41 8b 55 0c 48 8d 1c d0 <0f> b6 03 83 e0 0f 3c 0f 0f 85 a2 00 00 00 e9 e6 01 00 00 0f b7 ee
    [ 149.991952] RSP: 0018:ffffc9000f1ebcb8 EFLAGS: 00010246 [ 150.000937] RAX: 0000000000000055 RBX:
    00000007fffc445d RCX: 000000002548f071 [ 150.011841] RDX: 00000000ffff8881 RSI: 0000000000000001 RDI:
    ffff888125ed50d8 [ 150.022670] RBP: 0000000000000000 R08: 0000000000000000 R09: c0000000ffff7fff [
    150.033445] R10: ffffc9000f1ebb68 R11: ffffc9000f1ebb60 R12: 0000000000000000 [ 150.044204] R13:
    ffff888125ed50d8 R14: 0000000000000080 R15: 34cdc00034cdea80 [ 150.054963] FS: 0000000000000000(0000)
    GS:ffff88dfaf200000(0000) knlGS:0000000000000000 [ 150.066715] CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 [ 150.076078] CR2: 00000007fffc445d CR3: 000000012448a006 CR4: 0000000000770ee0 [
    150.086887] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [ 150.097670] DR3:
    0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 150.108323] PKRU: 55555554 [ 150.114690]
    Call Trace: [ 150.120497] ? printk+0x48/0x4a [ 150.127049] mpt3sas_scsih_issue_tm.cold.114+0x2e/0x2b3
    [mpt3sas] [ 150.136453] mpt3sas_scsih_issue_locked_tm+0x86/0xb0 [mpt3sas] [ 150.145759]
    scsih_dev_reset+0xea/0x300 [mpt3sas] [ 150.153891] scsi_eh_ready_devs+0x541/0x9e0 [scsi_mod] [ 150.162206]
    ? __scsi_host_match+0x20/0x20 [scsi_mod] [ 150.170406] ? scsi_try_target_reset+0x90/0x90 [scsi_mod] [
    150.178925] ? blk_mq_tagset_busy_iter+0x45/0x60 [ 150.186638] ? scsi_try_target_reset+0x90/0x90 [scsi_mod]
    [ 150.195087] scsi_error_handler+0x3a5/0x4a0 [scsi_mod] [ 150.203206] ? __schedule+0x1e9/0x610 [
    150.209783] ? scsi_eh_get_sense+0x210/0x210 [scsi_mod] [ 150.217924] kthread+0x12e/0x150 [ 150.224041] ?
    kthread_worker_fn+0x130/0x130 [ 150.231206] ret_from_fork+0x1f/0x30 This is caused by
    mpt3sas_base_sync_reply_irqs() using an invalid reply_q pointer outside of the list_for_each_entry() loop.
    At the end of the full list traversal the pointer is invalid. Move the _base_process_reply_queue() call
    inside of the loop. (CVE-2022-48835)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48835");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
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
    "name": [
     "linux-aws-cloud-tools-5.15.0-1004",
     "linux-aws-headers-5.15.0-1004",
     "linux-aws-tools-5.15.0-1004",
     "linux-azure-cloud-tools-5.15.0-1003",
     "linux-azure-headers-5.15.0-1003",
     "linux-azure-tools-5.15.0-1003",
     "linux-buildinfo-5.15.0-1002-gke",
     "linux-buildinfo-5.15.0-1002-ibm",
     "linux-buildinfo-5.15.0-1002-oracle",
     "linux-buildinfo-5.15.0-1003-azure",
     "linux-buildinfo-5.15.0-1003-gcp",
     "linux-buildinfo-5.15.0-1004-aws",
     "linux-buildinfo-5.15.0-1004-kvm",
     "linux-buildinfo-5.15.0-24-lowlatency",
     "linux-buildinfo-5.15.0-24-lowlatency-64k",
     "linux-buildinfo-5.15.0-25-generic",
     "linux-buildinfo-5.15.0-25-generic-64k",
     "linux-cloud-tools-5.15.0-1002-ibm",
     "linux-cloud-tools-5.15.0-1002-oracle",
     "linux-cloud-tools-5.15.0-1003-azure",
     "linux-cloud-tools-5.15.0-1004-aws",
     "linux-cloud-tools-5.15.0-1004-kvm",
     "linux-cloud-tools-5.15.0-24-lowlatency",
     "linux-cloud-tools-5.15.0-24-lowlatency-64k",
     "linux-cloud-tools-5.15.0-25",
     "linux-cloud-tools-5.15.0-25-generic",
     "linux-cloud-tools-5.15.0-25-generic-64k",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-headers-5.15.0-1003",
     "linux-gcp-tools-5.15.0-1003",
     "linux-gke-headers-5.15.0-1002",
     "linux-gke-tools-5.15.0-1002",
     "linux-headers-5.15.0-1002-gke",
     "linux-headers-5.15.0-1002-ibm",
     "linux-headers-5.15.0-1002-oracle",
     "linux-headers-5.15.0-1003-azure",
     "linux-headers-5.15.0-1003-gcp",
     "linux-headers-5.15.0-1004-aws",
     "linux-headers-5.15.0-1004-kvm",
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
     "linux-modules-5.15.0-1004-kvm",
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
     "linux-modules-extra-5.15.0-1004-kvm",
     "linux-modules-extra-5.15.0-24-lowlatency",
     "linux-modules-extra-5.15.0-24-lowlatency-64k",
     "linux-modules-extra-5.15.0-25-generic",
     "linux-modules-extra-5.15.0-25-generic-64k",
     "linux-modules-extra-5.15.0-25-generic-lpae",
     "linux-oracle-headers-5.15.0-1002",
     "linux-oracle-tools-5.15.0-1002",
     "linux-source-5.15.0",
     "linux-tools-5.15.0-1002-gke",
     "linux-tools-5.15.0-1002-ibm",
     "linux-tools-5.15.0-1002-oracle",
     "linux-tools-5.15.0-1003-azure",
     "linux-tools-5.15.0-1003-gcp",
     "linux-tools-5.15.0-1004-aws",
     "linux-tools-5.15.0-1004-kvm",
     "linux-tools-5.15.0-24-lowlatency",
     "linux-tools-5.15.0-24-lowlatency-64k",
     "linux-tools-5.15.0-25",
     "linux-tools-5.15.0-25-generic",
     "linux-tools-5.15.0-25-generic-64k",
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
