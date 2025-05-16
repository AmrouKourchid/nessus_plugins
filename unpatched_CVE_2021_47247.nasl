#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224328);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47247");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47247");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Fix use-after-free of encap
    entry in neigh update handler Function mlx5e_rep_neigh_update() wasn't updated to accommodate rtnl lock
    removal from TC filter update path and properly handle concurrent encap entry insertion/deletion which can
    lead to following use-after-free: [23827.464923]
    ================================================================== [23827.469446] BUG: KASAN: use-after-
    free in mlx5e_encap_take+0x72/0x140 [mlx5_core] [23827.470971] Read of size 4 at addr ffff8881d132228c by
    task kworker/u20:6/21635 [23827.472251] [23827.472615] CPU: 9 PID: 21635 Comm: kworker/u20:6 Not tainted
    5.13.0-rc3+ #5 [23827.473788] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
    rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 [23827.475639] Workqueue: mlx5e
    mlx5e_rep_neigh_update [mlx5_core] [23827.476731] Call Trace: [23827.477260] dump_stack+0xbb/0x107
    [23827.477906] print_address_description.constprop.0+0x18/0x140 [23827.478896] ?
    mlx5e_encap_take+0x72/0x140 [mlx5_core] [23827.479879] ? mlx5e_encap_take+0x72/0x140 [mlx5_core]
    [23827.480905] kasan_report.cold+0x7c/0xd8 [23827.481701] ? mlx5e_encap_take+0x72/0x140 [mlx5_core]
    [23827.482744] kasan_check_range+0x145/0x1a0 [23827.493112] mlx5e_encap_take+0x72/0x140 [mlx5_core]
    [23827.494054] ? mlx5e_tc_tun_encap_info_equal_generic+0x140/0x140 [mlx5_core] [23827.495296]
    mlx5e_rep_neigh_update+0x41e/0x5e0 [mlx5_core] [23827.496338] ? mlx5e_rep_neigh_entry_release+0xb80/0xb80
    [mlx5_core] [23827.497486] ? read_word_at_a_time+0xe/0x20 [23827.498250] ? strscpy+0xa0/0x2a0
    [23827.498889] process_one_work+0x8ac/0x14e0 [23827.499638] ? lockdep_hardirqs_on_prepare+0x400/0x400
    [23827.500537] ? pwq_dec_nr_in_flight+0x2c0/0x2c0 [23827.501359] ? rwlock_bug.part.0+0x90/0x90
    [23827.502116] worker_thread+0x53b/0x1220 [23827.502831] ? process_one_work+0x14e0/0x14e0 [23827.503627]
    kthread+0x328/0x3f0 [23827.504254] ? _raw_spin_unlock_irq+0x24/0x40 [23827.505065] ?
    __kthread_bind_mask+0x90/0x90 [23827.505912] ret_from_fork+0x1f/0x30 [23827.506621] [23827.506987]
    Allocated by task 28248: [23827.507694] kasan_save_stack+0x1b/0x40 [23827.508476]
    __kasan_kmalloc+0x7c/0x90 [23827.509197] mlx5e_attach_encap+0xde1/0x1d40 [mlx5_core] [23827.510194]
    mlx5e_tc_add_fdb_flow+0x397/0xc40 [mlx5_core] [23827.511218] __mlx5e_add_fdb_flow+0x519/0xb30 [mlx5_core]
    [23827.512234] mlx5e_configure_flower+0x191c/0x4870 [mlx5_core] [23827.513298] tc_setup_cb_add+0x1d5/0x420
    [23827.514023] fl_hw_replace_filter+0x382/0x6a0 [cls_flower] [23827.514975] fl_change+0x2ceb/0x4a51
    [cls_flower] [23827.515821] tc_new_tfilter+0x89a/0x2070 [23827.516548] rtnetlink_rcv_msg+0x644/0x8c0
    [23827.517300] netlink_rcv_skb+0x11d/0x340 [23827.518021] netlink_unicast+0x42b/0x700 [23827.518742]
    netlink_sendmsg+0x743/0xc20 [23827.519467] sock_sendmsg+0xb2/0xe0 [23827.520131]
    ____sys_sendmsg+0x590/0x770 [23827.520851] ___sys_sendmsg+0xd8/0x160 [23827.521552]
    __sys_sendmsg+0xb7/0x140 [23827.522238] do_syscall_64+0x3a/0x70 [23827.522907]
    entry_SYSCALL_64_after_hwframe+0x44/0xae [23827.523797] [23827.524163] Freed by task 25948: [23827.524780]
    kasan_save_stack+0x1b/0x40 [23827.525488] kasan_set_track+0x1c/0x30 [23827.526187]
    kasan_set_free_info+0x20/0x30 [23827.526968] __kasan_slab_free+0xed/0x130 [23827.527709]
    slab_free_freelist_hook+0xcf/0x1d0 [23827.528528] kmem_cache_free_bulk+0x33a/0x6e0 [23827.529317]
    kfree_rcu_work+0x55f/0xb70 [23827.530024] process_one_work+0x8ac/0x14e0 [23827.530770]
    worker_thread+0x53b/0x1220 [23827.531480] kthread+0x328/0x3f0 [23827.532114] ret_from_fork+0x1f/0x30
    [23827.532785] [23827.533147] Last potentially related work creation: [23827.534007]
    kasan_save_stack+0x1b/0x40 [23827.534710] kasan_record_aux_stack+0xab/0xc0 [23827.535492]
    kvfree_call_rcu+0x31/0x7b0 [23827.536206] mlx5e_tc_del ---truncated--- (CVE-2021-47247)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
        "os_version": "8"
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
