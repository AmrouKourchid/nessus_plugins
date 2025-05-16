#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226772);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52516");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52516");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: dma-debug: don't call
    __dma_entry_alloc_check_leak() under free_entries_lock __dma_entry_alloc_check_leak() calls into printk ->
    serial console output (qcom geni) and grabs port->lock under free_entries_lock spin lock, which is a
    reverse locking dependency chain as qcom_geni IRQ handler can call into dma-debug code and grab
    free_entries_lock under port->lock. Move __dma_entry_alloc_check_leak() call out of free_entries_lock
    scope so that we don't acquire serial console's port->lock under it. Trimmed-down lockdep splat: The
    existing dependency chain (in reverse order) is: -> #2 (free_entries_lock){-.-.}-{2:2}:
    _raw_spin_lock_irqsave+0x60/0x80 dma_entry_alloc+0x38/0x110 debug_dma_map_page+0x60/0xf8
    dma_map_page_attrs+0x1e0/0x230 dma_map_single_attrs.constprop.0+0x6c/0xc8 geni_se_rx_dma_prep+0x40/0xcc
    qcom_geni_serial_isr+0x310/0x510 __handle_irq_event_percpu+0x110/0x244 handle_irq_event_percpu+0x20/0x54
    handle_irq_event+0x50/0x88 handle_fasteoi_irq+0xa4/0xcc handle_irq_desc+0x28/0x40
    generic_handle_domain_irq+0x24/0x30 gic_handle_irq+0xc4/0x148 do_interrupt_handler+0xa4/0xb0
    el1_interrupt+0x34/0x64 el1h_64_irq_handler+0x18/0x24 el1h_64_irq+0x64/0x68 arch_local_irq_enable+0x4/0x8
    ____do_softirq+0x18/0x24 ... -> #1 (&port_lock_key){-.-.}-{2:2}: _raw_spin_lock_irqsave+0x60/0x80
    qcom_geni_serial_console_write+0x184/0x1dc console_flush_all+0x344/0x454 console_unlock+0x94/0xf0
    vprintk_emit+0x238/0x24c vprintk_default+0x3c/0x48 vprintk+0xb4/0xbc _printk+0x68/0x90
    register_console+0x230/0x38c uart_add_one_port+0x338/0x494 qcom_geni_serial_probe+0x390/0x424
    platform_probe+0x70/0xc0 really_probe+0x148/0x280 __driver_probe_device+0xfc/0x114
    driver_probe_device+0x44/0x100 __device_attach_driver+0x64/0xdc bus_for_each_drv+0xb0/0xd8
    __device_attach+0xe4/0x140 device_initial_probe+0x1c/0x28 bus_probe_device+0x44/0xb0
    device_add+0x538/0x668 of_device_add+0x44/0x50 of_platform_device_create_pdata+0x94/0xc8
    of_platform_bus_create+0x270/0x304 of_platform_populate+0xac/0xc4 devm_of_platform_populate+0x60/0xac
    geni_se_probe+0x154/0x160 platform_probe+0x70/0xc0 ... -> #0 (console_owner){-...}-{0:0}:
    __lock_acquire+0xdf8/0x109c lock_acquire+0x234/0x284 console_flush_all+0x330/0x454
    console_unlock+0x94/0xf0 vprintk_emit+0x238/0x24c vprintk_default+0x3c/0x48 vprintk+0xb4/0xbc
    _printk+0x68/0x90 dma_entry_alloc+0xb4/0x110 debug_dma_map_sg+0xdc/0x2f8 __dma_map_sg_attrs+0xac/0xe4
    dma_map_sgtable+0x30/0x4c get_pages+0x1d4/0x1e4 [msm] msm_gem_pin_pages_locked+0x38/0xac [msm]
    msm_gem_pin_vma_locked+0x58/0x88 [msm] msm_ioctl_gem_submit+0xde4/0x13ac [msm] drm_ioctl_kernel+0xe0/0x15c
    drm_ioctl+0x2e8/0x3f4 vfs_ioctl+0x30/0x50 ... Chain exists of: console_owner --> &port_lock_key -->
    free_entries_lock Possible unsafe locking scenario: CPU0 CPU1 ---- ---- lock(free_entries_lock);
    lock(&port_lock_key); lock(free_entries_lock); lock(console_owner); *** DEADLOCK *** Call trace:
    dump_backtrace+0xb4/0xf0 show_stack+0x20/0x30 dump_stack_lvl+0x60/0x84 dump_stack+0x18/0x24
    print_circular_bug+0x1cc/0x234 check_noncircular+0x78/0xac __lock_acquire+0xdf8/0x109c
    lock_acquire+0x234/0x284 console_flush_all+0x330/0x454 consol ---truncated--- (CVE-2023-52516)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
