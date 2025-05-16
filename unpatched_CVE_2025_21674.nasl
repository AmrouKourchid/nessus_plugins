#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230660);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-21674");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-21674");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Fix inversion dependency
    warning while enabling IPsec tunnel Attempt to enable IPsec packet offload in tunnel mode in debug kernel
    generates the following kernel panic, which is happening due to two issues: 1. In SA add section, the
    should be _bh() variant when marking SA mode. 2. There is not needed flush_workqueue in SA delete routine.
    It is not needed as at this stage as it is removed from SADB and the running work will be canceled later
    in SA free. ===================================================== WARNING: SOFTIRQ-safe -> SOFTIRQ-unsafe
    lock order detected 6.12.0+ #4 Not tainted -----------------------------------------------------
    charon/1337 [HC0[0]:SC0[4]:HE1:SE0] is trying to acquire: ffff88810f365020 (&xa->xa_lock#24){+.+.}-{3:3},
    at: mlx5e_xfrm_del_state+0xca/0x1e0 [mlx5_core] and this task is already holding: ffff88813e0f0d48
    (&x->lock){+.-.}-{3:3}, at: xfrm_state_delete+0x16/0x30 which would create a new lock dependency:
    (&x->lock){+.-.}-{3:3} -> (&xa->xa_lock#24){+.+.}-{3:3} but this new dependency connects a SOFTIRQ-irq-
    safe lock: (&x->lock){+.-.}-{3:3} ... which became SOFTIRQ-irq-safe at: lock_acquire+0x1be/0x520
    _raw_spin_lock_bh+0x34/0x40 xfrm_timer_handler+0x91/0xd70 __hrtimer_run_queues+0x1dd/0xa60
    hrtimer_run_softirq+0x146/0x2e0 handle_softirqs+0x266/0x860 irq_exit_rcu+0x115/0x1a0
    sysvec_apic_timer_interrupt+0x6e/0x90 asm_sysvec_apic_timer_interrupt+0x16/0x20 default_idle+0x13/0x20
    default_idle_call+0x67/0xa0 do_idle+0x2da/0x320 cpu_startup_entry+0x50/0x60 start_secondary+0x213/0x2a0
    common_startup_64+0x129/0x138 to a SOFTIRQ-irq-unsafe lock: (&xa->xa_lock#24){+.+.}-{3:3} ... which became
    SOFTIRQ-irq-unsafe at: ... lock_acquire+0x1be/0x520 _raw_spin_lock+0x2c/0x40 xa_set_mark+0x70/0x110
    mlx5e_xfrm_add_state+0xe48/0x2290 [mlx5_core] xfrm_dev_state_add+0x3bb/0xd70 xfrm_add_sa+0x2451/0x4a90
    xfrm_user_rcv_msg+0x493/0x880 netlink_rcv_skb+0x12e/0x380 xfrm_netlink_rcv+0x6d/0x90
    netlink_unicast+0x42f/0x740 netlink_sendmsg+0x745/0xbe0 __sock_sendmsg+0xc5/0x190 __sys_sendto+0x1fe/0x2c0
    __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x6d/0x140 entry_SYSCALL_64_after_hwframe+0x4b/0x53 other info
    that might help us debug this: Possible interrupt unsafe locking scenario: CPU0 CPU1 ---- ----
    lock(&xa->xa_lock#24); local_irq_disable(); lock(&x->lock); lock(&xa->xa_lock#24); <Interrupt>
    lock(&x->lock); *** DEADLOCK *** 2 locks held by charon/1337: #0: ffffffff87f8f858
    (&net->xfrm.xfrm_cfg_mutex){+.+.}-{4:4}, at: xfrm_netlink_rcv+0x5e/0x90 #1: ffff88813e0f0d48
    (&x->lock){+.-.}-{3:3}, at: xfrm_state_delete+0x16/0x30 the dependencies between SOFTIRQ-irq-safe lock and
    the holding lock: -> (&x->lock){+.-.}-{3:3} ops: 29 { HARDIRQ-ON-W at: lock_acquire+0x1be/0x520
    _raw_spin_lock_bh+0x34/0x40 xfrm_alloc_spi+0xc0/0xe60 xfrm_alloc_userspi+0x5f6/0xbc0
    xfrm_user_rcv_msg+0x493/0x880 netlink_rcv_skb+0x12e/0x380 xfrm_netlink_rcv+0x6d/0x90
    netlink_unicast+0x42f/0x740 netlink_sendmsg+0x745/0xbe0 __sock_sendmsg+0xc5/0x190 __sys_sendto+0x1fe/0x2c0
    __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x6d/0x140 entry_SYSCALL_64_after_hwframe+0x4b/0x53 IN-SOFTIRQ-W
    at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_timer_handler+0x91/0xd70
    __hrtimer_run_queues+0x1dd/0xa60 ---truncated--- (CVE-2025-21674)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
