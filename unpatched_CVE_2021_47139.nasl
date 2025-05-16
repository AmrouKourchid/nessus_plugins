#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224420);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47139");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47139");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: hns3: put off calling
    register_netdev() until client initialize complete Currently, the netdevice is registered before client
    initializing complete. So there is a timewindow between netdevice available and usable. In this case, if
    user try to change the channel number or ring param, it may cause the hns3_set_rx_cpu_rmap() being called
    twice, and report bug. [47199.416502] hns3 0000:35:00.0 eth1: set channels: tqp_num=1, rxfh=0
    [47199.430340] hns3 0000:35:00.0 eth1: already uninitialized [47199.438554] hns3 0000:35:00.0: rss changes
    from 4 to 1 [47199.511854] hns3 0000:35:00.0: Channels changed, rss_size from 4 to 1, tqps from 4 to 1
    [47200.163524] ------------[ cut here ]------------ [47200.171674] kernel BUG at lib/cpu_rmap.c:142!
    [47200.177847] Internal error: Oops - BUG: 0 [#1] PREEMPT SMP [47200.185259] Modules linked in: hclge(+)
    hns3(-) hns3_cae(O) hns_roce_hw_v2 hnae3 vfio_iommu_type1 vfio_pci vfio_virqfd vfio pv680_mii(O) [last
    unloaded: hclge] [47200.205912] CPU: 1 PID: 8260 Comm: ethtool Tainted: G O 5.11.0-rc3+ #1 [47200.215601]
    Hardware name: , xxxxxx 02/04/2021 [47200.223052] pstate: 60400009 (nZCv daif +PAN -UAO -TCO BTYPE=--)
    [47200.230188] pc : cpu_rmap_add+0x38/0x40 [47200.237472] lr : irq_cpu_rmap_add+0x84/0x140 [47200.243291]
    sp : ffff800010e93a30 [47200.247295] x29: ffff800010e93a30 x28: ffff082100584880 [47200.254155] x27:
    0000000000000000 x26: 0000000000000000 [47200.260712] x25: 0000000000000000 x24: 0000000000000004
    [47200.267241] x23: ffff08209ba03000 x22: ffff08209ba038c0 [47200.273789] x21: 000000000000003f x20:
    ffff0820e2bc1680 [47200.280400] x19: ffff0820c970ec80 x18: 00000000000000c0 [47200.286944] x17:
    0000000000000000 x16: ffffb43debe4a0d0 [47200.293456] x15: fffffc2082990600 x14: dead000000000122
    [47200.300059] x13: ffffffffffffffff x12: 000000000000003e [47200.306606] x11: ffff0820815b8080 x10:
    ffff53e411988000 [47200.313171] x9 : 0000000000000000 x8 : ffff0820e2bc1700 [47200.319682] x7 :
    0000000000000000 x6 : 000000000000003f [47200.326170] x5 : 0000000000000040 x4 : ffff800010e93a20
    [47200.332656] x3 : 0000000000000004 x2 : ffff0820c970ec80 [47200.339168] x1 : ffff0820e2bc1680 x0 :
    0000000000000004 [47200.346058] Call trace: [47200.349324] cpu_rmap_add+0x38/0x40 [47200.354300]
    hns3_set_rx_cpu_rmap+0x6c/0xe0 [hns3] [47200.362294] hns3_reset_notify_init_enet+0x1cc/0x340 [hns3]
    [47200.370049] hns3_change_channels+0x40/0xb0 [hns3] [47200.376770] hns3_set_channels+0x12c/0x2a0 [hns3]
    [47200.383353] ethtool_set_channels+0x140/0x250 [47200.389772] dev_ethtool+0x714/0x23d0 [47200.394440]
    dev_ioctl+0x4cc/0x640 [47200.399277] sock_do_ioctl+0x100/0x2a0 [47200.404574] sock_ioctl+0x28c/0x470
    [47200.409079] __arm64_sys_ioctl+0xb4/0x100 [47200.415217] el0_svc_common.constprop.0+0x84/0x210
    [47200.422088] do_el0_svc+0x28/0x34 [47200.426387] el0_svc+0x28/0x70 [47200.431308]
    el0_sync_handler+0x1a4/0x1b0 [47200.436477] el0_sync+0x174/0x180 [47200.441562] Code: 11000405 79000c45
    f8247861 d65f03c0 (d4210000) [47200.448869] ---[ end trace a01efe4ce42e5f34 ]--- The process is like
    below: excuting hns3_client_init | register_netdev() | hns3_set_channels() | | hns3_set_rx_cpu_rmap()
    hns3_reset_notify_uninit_enet() | | | quit without calling function | hns3_free_rx_cpu_rmap for flag |
    HNS3_NIC_STATE_INITED is unset. | | | hns3_reset_notify_init_enet() | | set HNS3_NIC_STATE_INITED call
    hns3_set_rx_cpu_rmap()-- crash Fix it by calling register_netdev() at the end of function
    hns3_client_init(). (CVE-2021-47139)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47139");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
