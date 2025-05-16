#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231649);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-21729");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-21729");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: rtw89: fix race between
    cancel_hw_scan and hw_scan completion The rtwdev->scanning flag isn't protected by mutex originally, so
    cancel_hw_scan can pass the condition, but suddenly hw_scan completion unset the flag and calls
    ieee80211_scan_completed() that will free local->hw_scan_req. Then, cancel_hw_scan raises null-ptr-deref
    and use-after-free. Fix it by moving the check condition to where protected by mutex. KASAN: null-ptr-
    deref in range [0x0000000000000088-0x000000000000008f] CPU: 2 PID: 6922 Comm: kworker/2:2 Tainted: G OE
    Hardware name: LENOVO 2356AD1/2356AD1, BIOS G7ETB6WW (2.76 ) 09/10/2019 Workqueue: events
    cfg80211_conn_work [cfg80211] RIP: 0010:rtw89_fw_h2c_scan_offload_be+0xc33/0x13c3 [rtw89_core] Code: 00 45
    89 6c 24 1c 0f 85 23 01 00 00 48 8b 85 20 ff ff ff 48 8d RSP: 0018:ffff88811fd9f068 EFLAGS: 00010206 RAX:
    dffffc0000000000 RBX: ffff88811fd9f258 RCX: 0000000000000001 RDX: 0000000000000011 RSI: 0000000000000001
    RDI: 0000000000000089 RBP: ffff88811fd9f170 R08: 0000000000000000 R09: 0000000000000000 R10:
    ffff88811fd9f108 R11: 0000000000000000 R12: ffff88810e47f960 R13: 0000000000000000 R14: 000000000000ffff
    R15: 0000000000000000 FS: 0000000000000000(0000) GS:ffff8881d6f00000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007531dfca55b0 CR3: 00000001be296004 CR4: 00000000001706e0
    Call Trace: <TASK> ? show_regs+0x61/0x73 ? __die_body+0x20/0x73 ? die_addr+0x4f/0x7b ?
    exc_general_protection+0x191/0x1db ? asm_exc_general_protection+0x27/0x30 ?
    rtw89_fw_h2c_scan_offload_be+0xc33/0x13c3 [rtw89_core] ? rtw89_fw_h2c_scan_offload_be+0x458/0x13c3
    [rtw89_core] ? __pfx_rtw89_fw_h2c_scan_offload_be+0x10/0x10 [rtw89_core] ? do_raw_spin_lock+0x75/0xdb ?
    __pfx_do_raw_spin_lock+0x10/0x10 rtw89_hw_scan_offload+0xb5e/0xbf7 [rtw89_core] ?
    _raw_spin_unlock+0xe/0x24 ? __mutex_lock.constprop.0+0x40c/0x471 ? __pfx_rtw89_hw_scan_offload+0x10/0x10
    [rtw89_core] ? __mutex_lock_slowpath+0x13/0x1f ? mutex_lock+0xa2/0xdc ? __pfx_mutex_lock+0x10/0x10
    rtw89_hw_scan_abort+0x58/0xb7 [rtw89_core] rtw89_ops_cancel_hw_scan+0x120/0x13b [rtw89_core]
    ieee80211_scan_cancel+0x468/0x4d0 [mac80211] ieee80211_prep_connection+0x858/0x899 [mac80211]
    ieee80211_mgd_auth+0xbea/0xdde [mac80211] ? __pfx_ieee80211_mgd_auth+0x10/0x10 [mac80211] ?
    cfg80211_find_elem+0x15/0x29 [cfg80211] ? is_bss+0x1b7/0x1d7 [cfg80211] ieee80211_auth+0x18/0x27
    [mac80211] cfg80211_mlme_auth+0x3bb/0x3e7 [cfg80211] cfg80211_conn_do_work+0x410/0xb81 [cfg80211] ?
    __pfx_cfg80211_conn_do_work+0x10/0x10 [cfg80211] ? __kasan_check_read+0x11/0x1f ?
    psi_group_change+0x8bc/0x944 ? __kasan_check_write+0x14/0x22 ? mutex_lock+0x8e/0xdc ?
    __pfx_mutex_lock+0x10/0x10 ? __pfx___radix_tree_lookup+0x10/0x10 cfg80211_conn_work+0x245/0x34d [cfg80211]
    ? __pfx_cfg80211_conn_work+0x10/0x10 [cfg80211] ? update_cfs_rq_load_avg+0x3bc/0x3d7 ?
    sched_clock_noinstr+0x9/0x1a ? sched_clock+0x10/0x24 ? sched_clock_cpu+0x7e/0x42e ?
    newidle_balance+0x796/0x937 ? __pfx_sched_clock_cpu+0x10/0x10 ? __pfx_newidle_balance+0x10/0x10 ?
    __kasan_check_read+0x11/0x1f ? psi_group_change+0x8bc/0x944 ? _raw_spin_unlock+0xe/0x24 ?
    raw_spin_rq_unlock+0x47/0x54 ? raw_spin_rq_unlock_irq+0x9/0x1f ? finish_task_switch.isra.0+0x347/0x586 ?
    __schedule+0x27bf/0x2892 ? mutex_unlock+0x80/0xd0 ? do_raw_spin_lock+0x75/0xdb ?
    __pfx___schedule+0x10/0x10 process_scheduled_works+0x58c/0x821 worker_thread+0x4c7/0x586 ?
    __kasan_check_read+0x11/0x1f kthread+0x285/0x294 ? __pfx_worker_thread+0x10/0x10 ? __pfx_kthread+0x10/0x10
    ret_from_fork+0x29/0x6f ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK> (CVE-2025-21729)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "bpftool",
     "hyperv-daemons",
     "intel-sdsi",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bpf-dev",
     "linux-config-6.12",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-6.12",
     "linux-headers-4kc-malta",
     "linux-headers-5kc-malta",
     "linux-headers-6.12.12-4kc-malta",
     "linux-headers-6.12.12-5kc-malta",
     "linux-headers-6.12.12-alpha-generic",
     "linux-headers-6.12.12-alpha-smp",
     "linux-headers-6.12.12-amd64",
     "linux-headers-6.12.12-arm64",
     "linux-headers-6.12.12-arm64-16k",
     "linux-headers-6.12.12-armmp",
     "linux-headers-6.12.12-armmp-lpae",
     "linux-headers-6.12.12-cloud-amd64",
     "linux-headers-6.12.12-cloud-arm64",
     "linux-headers-6.12.12-common",
     "linux-headers-6.12.12-common-rt",
     "linux-headers-6.12.12-loong64",
     "linux-headers-6.12.12-loongson-3",
     "linux-headers-6.12.12-m68k",
     "linux-headers-6.12.12-mips32r2eb",
     "linux-headers-6.12.12-mips32r2el",
     "linux-headers-6.12.12-mips64r2eb",
     "linux-headers-6.12.12-mips64r2el",
     "linux-headers-6.12.12-mips64r6el",
     "linux-headers-6.12.12-octeon",
     "linux-headers-6.12.12-parisc",
     "linux-headers-6.12.12-parisc64"
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
        "os_version": "13"
       }
      }
     ]
    }
   ]
  },
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
     "linux-hwe-6.11",
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
     "linux-oem-6.11",
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
     "linux-aws-cloud-tools-6.11.0-1004",
     "linux-aws-headers-6.11.0-1004",
     "linux-aws-tools-6.11.0-1004",
     "linux-azure-cloud-tools-6.11.0-1004",
     "linux-azure-headers-6.11.0-1004",
     "linux-azure-tools-6.11.0-1004",
     "linux-bpf-dev",
     "linux-buildinfo-6.11.0-1003-gcp",
     "linux-buildinfo-6.11.0-1004-aws",
     "linux-buildinfo-6.11.0-1004-azure",
     "linux-buildinfo-6.11.0-1004-lowlatency",
     "linux-buildinfo-6.11.0-1004-lowlatency-64k",
     "linux-buildinfo-6.11.0-1004-raspi",
     "linux-buildinfo-6.11.0-1006-oracle",
     "linux-buildinfo-6.11.0-1006-oracle-64k",
     "linux-buildinfo-6.11.0-8-generic",
     "linux-cloud-tools-6.11.0-1004-aws",
     "linux-cloud-tools-6.11.0-1004-azure",
     "linux-cloud-tools-6.11.0-1004-lowlatency",
     "linux-cloud-tools-6.11.0-1004-lowlatency-64k",
     "linux-cloud-tools-6.11.0-1006-oracle",
     "linux-cloud-tools-6.11.0-1006-oracle-64k",
     "linux-cloud-tools-6.11.0-8",
     "linux-cloud-tools-6.11.0-8-generic",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-headers-6.11.0-1003",
     "linux-gcp-tools-6.11.0-1003",
     "linux-headers-6.11.0-1003-gcp",
     "linux-headers-6.11.0-1004-aws",
     "linux-headers-6.11.0-1004-azure",
     "linux-headers-6.11.0-1004-lowlatency",
     "linux-headers-6.11.0-1004-lowlatency-64k",
     "linux-headers-6.11.0-1004-raspi",
     "linux-headers-6.11.0-1006-oracle",
     "linux-headers-6.11.0-1006-oracle-64k",
     "linux-headers-6.11.0-8",
     "linux-headers-6.11.0-8-generic",
     "linux-headers-6.11.0-8-generic-64k",
     "linux-image-6.11.0-1004-raspi",
     "linux-image-6.11.0-1004-raspi-dbgsym",
     "linux-image-6.11.0-8-generic",
     "linux-image-6.11.0-8-generic-dbgsym",
     "linux-image-unsigned-6.11.0-1003-gcp",
     "linux-image-unsigned-6.11.0-1003-gcp-dbgsym",
     "linux-image-unsigned-6.11.0-1004-aws",
     "linux-image-unsigned-6.11.0-1004-aws-dbgsym",
     "linux-image-unsigned-6.11.0-1004-azure",
     "linux-image-unsigned-6.11.0-1004-azure-dbgsym",
     "linux-image-unsigned-6.11.0-1004-lowlatency",
     "linux-image-unsigned-6.11.0-1004-lowlatency-64k",
     "linux-image-unsigned-6.11.0-1004-lowlatency-64k-dbgsym",
     "linux-image-unsigned-6.11.0-1004-lowlatency-dbgsym",
     "linux-image-unsigned-6.11.0-1006-oracle",
     "linux-image-unsigned-6.11.0-1006-oracle-64k",
     "linux-image-unsigned-6.11.0-1006-oracle-64k-dbgsym",
     "linux-image-unsigned-6.11.0-1006-oracle-dbgsym",
     "linux-image-unsigned-6.11.0-8-generic",
     "linux-image-unsigned-6.11.0-8-generic-64k",
     "linux-image-unsigned-6.11.0-8-generic-64k-dbgsym",
     "linux-image-unsigned-6.11.0-8-generic-dbgsym",
     "linux-lib-rust-6.11.0-8-generic",
     "linux-lib-rust-6.11.0-8-generic-64k",
     "linux-libc-dev",
     "linux-lowlatency-cloud-tools-6.11.0-1004",
     "linux-lowlatency-headers-6.11.0-1004",
     "linux-lowlatency-lib-rust-6.11.0-1004-lowlatency",
     "linux-lowlatency-lib-rust-6.11.0-1004-lowlatency-64k",
     "linux-lowlatency-tools-6.11.0-1004",
     "linux-modules-6.11.0-1003-gcp",
     "linux-modules-6.11.0-1004-aws",
     "linux-modules-6.11.0-1004-azure",
     "linux-modules-6.11.0-1004-lowlatency",
     "linux-modules-6.11.0-1004-lowlatency-64k",
     "linux-modules-6.11.0-1004-raspi",
     "linux-modules-6.11.0-1006-oracle",
     "linux-modules-6.11.0-1006-oracle-64k",
     "linux-modules-6.11.0-8-generic",
     "linux-modules-6.11.0-8-generic-64k",
     "linux-modules-extra-6.11.0-1003-gcp",
     "linux-modules-extra-6.11.0-1004-aws",
     "linux-modules-extra-6.11.0-1004-azure",
     "linux-modules-extra-6.11.0-1004-lowlatency",
     "linux-modules-extra-6.11.0-1004-lowlatency-64k",
     "linux-modules-extra-6.11.0-1006-oracle",
     "linux-modules-extra-6.11.0-1006-oracle-64k",
     "linux-modules-extra-6.11.0-8-generic",
     "linux-modules-extra-6.11.0-8-generic-64k",
     "linux-modules-ipu6-6.11.0-8-generic",
     "linux-modules-ipu7-6.11.0-8-generic",
     "linux-modules-iwlwifi-6.11.0-1004-azure",
     "linux-modules-iwlwifi-6.11.0-1004-lowlatency",
     "linux-modules-iwlwifi-6.11.0-1004-raspi",
     "linux-modules-iwlwifi-6.11.0-8-generic",
     "linux-modules-usbio-6.11.0-8-generic",
     "linux-modules-vision-6.11.0-8-generic",
     "linux-oracle-headers-6.11.0-1006",
     "linux-oracle-tools-6.11.0-1006",
     "linux-raspi-headers-6.11.0-1004",
     "linux-raspi-tools-6.11.0-1004",
     "linux-realtime",
     "linux-riscv-headers-6.11.0-8",
     "linux-riscv-tools-6.11.0-8",
     "linux-source-6.11.0",
     "linux-tools-6.11.0-1003-gcp",
     "linux-tools-6.11.0-1004-aws",
     "linux-tools-6.11.0-1004-azure",
     "linux-tools-6.11.0-1004-lowlatency",
     "linux-tools-6.11.0-1004-lowlatency-64k",
     "linux-tools-6.11.0-1004-raspi",
     "linux-tools-6.11.0-1006-oracle",
     "linux-tools-6.11.0-1006-oracle-64k",
     "linux-tools-6.11.0-8",
     "linux-tools-6.11.0-8-generic",
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
        "os_version": "24.10"
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
