#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228394);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-43834");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-43834");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: xdp: fix invalid wait context of
    page_pool_destroy() If the driver uses a page pool, it creates a page pool with page_pool_create(). The
    reference count of page pool is 1 as default. A page pool will be destroyed only when a reference count
    reaches 0. page_pool_destroy() is used to destroy page pool, it decreases a reference count. When a page
    pool is destroyed, ->disconnect() is called, which is mem_allocator_disconnect(). This function internally
    acquires mutex_lock(). If the driver uses XDP, it registers a memory model with
    xdp_rxq_info_reg_mem_model(). The xdp_rxq_info_reg_mem_model() internally increases a page pool reference
    count if a memory model is a page pool. Now the reference count is 2. To destroy a page pool, the driver
    should call both page_pool_destroy() and xdp_unreg_mem_model(). The xdp_unreg_mem_model() internally calls
    page_pool_destroy(). Only page_pool_destroy() decreases a reference count. If a driver calls
    page_pool_destroy() then xdp_unreg_mem_model(), we will face an invalid wait context warning. Because
    xdp_unreg_mem_model() calls page_pool_destroy() with rcu_read_lock(). The page_pool_destroy() internally
    acquires mutex_lock(). Splat looks like: ============================= [ BUG: Invalid wait context ]
    6.10.0-rc6+ #4 Tainted: G W ----------------------------- ethtool/1806 is trying to lock: ffffffff90387b90
    (mem_id_lock){+.+.}-{4:4}, at: mem_allocator_disconnect+0x73/0x150 other info that might help us debug
    this: context-{5:5} 3 locks held by ethtool/1806: stack backtrace: CPU: 0 PID: 1806 Comm: ethtool Tainted:
    G W 6.10.0-rc6+ #4 f916f41f172891c800f2fed Hardware name: ASUS System Product Name/PRIME Z690-P D4, BIOS
    0603 11/01/2021 Call Trace: <TASK> dump_stack_lvl+0x7e/0xc0 __lock_acquire+0x1681/0x4de0 ?
    _printk+0x64/0xe0 ? __pfx_mark_lock.part.0+0x10/0x10 ? __pfx___lock_acquire+0x10/0x10
    lock_acquire+0x1b3/0x580 ? mem_allocator_disconnect+0x73/0x150 ? __wake_up_klogd.part.0+0x16/0xc0 ?
    __pfx_lock_acquire+0x10/0x10 ? dump_stack_lvl+0x91/0xc0 __mutex_lock+0x15c/0x1690 ?
    mem_allocator_disconnect+0x73/0x150 ? __pfx_prb_read_valid+0x10/0x10 ? mem_allocator_disconnect+0x73/0x150
    ? __pfx_llist_add_batch+0x10/0x10 ? console_unlock+0x193/0x1b0 ? lockdep_hardirqs_on+0xbe/0x140 ?
    __pfx___mutex_lock+0x10/0x10 ? tick_nohz_tick_stopped+0x16/0x90 ? __irq_work_queue_local+0x1e5/0x330 ?
    irq_work_queue+0x39/0x50 ? __wake_up_klogd.part.0+0x79/0xc0 ? mem_allocator_disconnect+0x73/0x150
    mem_allocator_disconnect+0x73/0x150 ? __pfx_mem_allocator_disconnect+0x10/0x10 ? mark_held_locks+0xa5/0xf0
    ? rcu_is_watching+0x11/0xb0 page_pool_release+0x36e/0x6d0 page_pool_destroy+0xd7/0x440
    xdp_unreg_mem_model+0x1a7/0x2a0 ? __pfx_xdp_unreg_mem_model+0x10/0x10 ? kfree+0x125/0x370 ?
    bnxt_free_ring.isra.0+0x2eb/0x500 ? bnxt_free_mem+0x5ac/0x2500 xdp_rxq_info_unreg+0x4a/0xd0
    bnxt_free_mem+0x1356/0x2500 bnxt_close_nic+0xf0/0x3b0 ? __pfx_bnxt_close_nic+0x10/0x10 ?
    ethnl_parse_bit+0x2c6/0x6d0 ? __pfx___nla_validate_parse+0x10/0x10 ? __pfx_ethnl_parse_bit+0x10/0x10
    bnxt_set_features+0x2a8/0x3e0 __netdev_update_features+0x4dc/0x1370 ? ethnl_parse_bitset+0x4ff/0x750 ?
    __pfx_ethnl_parse_bitset+0x10/0x10 ? __pfx___netdev_update_features+0x10/0x10 ? mark_held_locks+0xa5/0xf0
    ? _raw_spin_unlock_irqrestore+0x42/0x70 ? __pm_runtime_resume+0x7d/0x110 ethnl_set_features+0x32d/0xa20 To
    fix this problem, it uses rhashtable_lookup_fast() instead of rhashtable_lookup() with rcu_read_lock().
    Using xa without rcu_read_lock() here is safe. xa is freed by __xdp_mem_allocator_rcu_free() and this is
    called by call_rcu() of mem_xa_remove(). The mem_xa_remove() is called by page_pool_destroy() if a
    reference count reaches 0. The xa is already protected by the reference count mechanism well in the
    control plane. So removing rcu_read_lock() for page_pool_destroy() is safe. (CVE-2024-43834)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43834");

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
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
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
    "name": "linux-azure-fde",
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
