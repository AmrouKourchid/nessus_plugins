#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228804);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-45005");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-45005");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: s390: fix validity interception
    issue when gisa is switched off We might run into a SIE validity if gisa has been disabled either via
    using kernel parameter kvm.use_gisa=0 or by setting the related sysfs attribute to N (echo N
    >/sys/module/kvm/parameters/use_gisa). The validity is caused by an invalid value in the SIE control
    block's gisa designation. That happens because we pass the uninitialized gisa origin to virt_to_phys()
    before writing it to the gisa designation. To fix this we return 0 in kvm_s390_get_gisa_desc() if the
    origin is 0. kvm_s390_get_gisa_desc() is used to determine which gisa designation to set in the SIE
    control block. A value of 0 in the gisa designation disables gisa usage. The issue surfaces in the host
    kernel with the following kernel message as soon a new kvm guest start is attemted. kvm: unhandled
    validity intercept 0x1011 WARNING: CPU: 0 PID: 781237 at arch/s390/kvm/intercept.c:101
    kvm_handle_sie_intercept+0x42e/0x4d0 [kvm] Modules linked in: vhost_net tap tun xt_CHECKSUM xt_MASQUERADE
    xt_conntrack ipt_REJECT xt_tcpudp nft_compat x_tables nf_nat_tftp nf_conntrack_tftp vfio_pci_core
    irqbypass vhost_vsock vmw_vsock_virtio_transport_common vsock vhost vhost_iotlb kvm nft_fib_inet
    nft_fib_ipv4 nft_fib_ipv6 nft_fib nft_reject_inet nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_ct
    nft_chain_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 ip_set nf_tables sunrpc mlx5_ib ib_uverbs
    ib_core mlx5_core uvdevice s390_trng eadm_sch vfio_ccw zcrypt_cex4 mdev vfio_iommu_type1 vfio sch_fq_codel
    drm i2c_core loop drm_panel_orientation_quirks configfs nfnetlink lcs ctcm fsm dm_service_time ghash_s390
    prng chacha_s390 libchacha aes_s390 des_s390 libdes sha3_512_s390 sha3_256_s390 sha512_s390 sha256_s390
    sha1_s390 sha_common dm_mirror dm_region_hash dm_log zfcp scsi_transport_fc scsi_dh_rdac scsi_dh_emc
    scsi_dh_alua pkey zcrypt dm_multipath rng_core autofs4 [last unloaded: vfio_pci] CPU: 0 PID: 781237 Comm:
    CPU 0/KVM Not tainted 6.10.0-08682-gcad9f11498ea #6 Hardware name: IBM 3931 A01 701 (LPAR) Krnl PSW :
    0704c00180000000 000003d93deb0122 (kvm_handle_sie_intercept+0x432/0x4d0 [kvm]) R:0 T:1 IO:1 EX:1 Key:0 M:1
    W:0 P:0 AS:3 CC:0 PM:0 RI:0 EA:3 Krnl GPRS: 000003d900000027 000003d900000023 0000000000000028
    000002cd00000000 000002d063a00900 00000359c6daf708 00000000000bebb5 0000000000001eff 000002cfd82e9000
    000002cfd80bc000 0000000000001011 000003d93deda412 000003ff8962df98 000003d93de77ce0 000003d93deb011e
    00000359c6daf960 Krnl Code: 000003d93deb0112: c020fffe7259 larl %r2,000003d93de7e5c4 000003d93deb0118:
    c0e53fa8beac brasl %r14,000003d9bd3c7e70 #000003d93deb011e: af000000 mc 0,0 >000003d93deb0122: a728ffea
    lhi %r2,-22 000003d93deb0126: a7f4fe24 brc 15,000003d93deafd6e 000003d93deb012a: 9101f0b0 tm 176(%r15),1
    000003d93deb012e: a774fe48 brc 7,000003d93deafdbe 000003d93deb0132: 40a0f0ae sth %r10,174(%r15) Call
    Trace: [<000003d93deb0122>] kvm_handle_sie_intercept+0x432/0x4d0 [kvm] ([<000003d93deb011e>]
    kvm_handle_sie_intercept+0x42e/0x4d0 [kvm]) [<000003d93deacc10>] vcpu_post_run+0x1d0/0x3b0 [kvm]
    [<000003d93deaceda>] __vcpu_run+0xea/0x2d0 [kvm] [<000003d93dead9da>] kvm_arch_vcpu_ioctl_run+0x16a/0x430
    [kvm] [<000003d93de93ee0>] kvm_vcpu_ioctl+0x190/0x7c0 [kvm] [<000003d9bd728b4e>] vfs_ioctl+0x2e/0x70
    [<000003d9bd72a092>] __s390x_sys_ioctl+0xc2/0xd0 [<000003d9be0e9222>] __do_syscall+0x1f2/0x2e0
    [<000003d9be0f9a90>] system_call+0x70/0x98 Last Breaking-Event-Address: [<000003d9bd3c7f58>]
    __warn_printk+0xe8/0xf0 (CVE-2024-45005)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45005");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
    "name": "kernel",
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
  },
  {
   "product": {
    "name": "kernel-rt",
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
