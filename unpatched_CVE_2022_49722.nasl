#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227281);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49722");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49722");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ice: Fix memory corruption in VF
    driver Disable VF's RX/TX queues, when it's disabled. VF can have queues enabled, when it requests a
    reset. If PF driver assumes that VF is disabled, while VF still has queues configured, VF may unmap DMA
    resources. In such scenario device still can map packets to memory, which ends up silently corrupting it.
    Previously, VF driver could experience memory corruption, which lead to crash: [ 5119.170157] BUG: unable
    to handle kernel paging request at 00001b9780003237 [ 5119.170166] PGD 0 P4D 0 [ 5119.170173] Oops: 0002
    [#1] PREEMPT_RT SMP PTI [ 5119.170181] CPU: 30 PID: 427592 Comm: kworker/u96:2 Kdump: loaded Tainted: G W
    I --------- - - 4.18.0-372.9.1.rt7.166.el8.x86_64 #1 [ 5119.170189] Hardware name: Dell Inc. PowerEdge
    R740/014X06, BIOS 2.3.10 08/15/2019 [ 5119.170193] Workqueue: iavf iavf_adminq_task [iavf] [ 5119.170219]
    RIP: 0010:__page_frag_cache_drain+0x5/0x30 [ 5119.170238] Code: 0f 0f b6 77 51 85 f6 74 07 31 d2 e9 05 df
    ff ff e9 90 fe ff ff 48 8b 05 49 db 33 01 eb b4 0f 1f 80 00 00 00 00 0f 1f 44 00 00 <f0> 29 77 34 74 01 c3
    48 8b 07 f6 c4 80 74 0f 0f b6 77 51 85 f6 74 [ 5119.170244] RSP: 0018:ffffa43b0bdcfd78 EFLAGS: 00010282 [
    5119.170250] RAX: ffffffff896b3e40 RBX: ffff8fb282524000 RCX: 0000000000000002 [ 5119.170254] RDX:
    0000000049000000 RSI: 0000000000000000 RDI: 00001b9780003203 [ 5119.170259] RBP: ffff8fb248217b00 R08:
    0000000000000022 R09: 0000000000000009 [ 5119.170262] R10: 2b849d6300000000 R11: 0000000000000020 R12:
    0000000000000000 [ 5119.170265] R13: 0000000000001000 R14: 0000000000000009 R15: 0000000000000000 [
    5119.170269] FS: 0000000000000000(0000) GS:ffff8fb1201c0000(0000) knlGS:0000000000000000 [ 5119.170274]
    CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 5119.170279] CR2: 00001b9780003237 CR3:
    00000008f3e1a003 CR4: 00000000007726e0 [ 5119.170283] DR0: 0000000000000000 DR1: 0000000000000000 DR2:
    0000000000000000 [ 5119.170286] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [
    5119.170290] PKRU: 55555554 [ 5119.170292] Call Trace: [ 5119.170298] iavf_clean_rx_ring+0xad/0x110 [iavf]
    [ 5119.170324] iavf_free_rx_resources+0xe/0x50 [iavf] [ 5119.170342]
    iavf_free_all_rx_resources.part.51+0x30/0x40 [iavf] [ 5119.170358] iavf_virtchnl_completion+0xd8a/0x15b0
    [iavf] [ 5119.170377] ? iavf_clean_arq_element+0x210/0x280 [iavf] [ 5119.170397]
    iavf_adminq_task+0x126/0x2e0 [iavf] [ 5119.170416] process_one_work+0x18f/0x420 [ 5119.170429]
    worker_thread+0x30/0x370 [ 5119.170437] ? process_one_work+0x420/0x420 [ 5119.170445] kthread+0x151/0x170
    [ 5119.170452] ? set_kthread_struct+0x40/0x40 [ 5119.170460] ret_from_fork+0x35/0x40 [ 5119.170477]
    Modules linked in: iavf sctp ip6_udp_tunnel udp_tunnel mlx4_en mlx4_core nfp tls vhost_net vhost
    vhost_iotlb tap tun xt_CHECKSUM ipt_MASQUERADE xt_conntrack ipt_REJECT nf_reject_ipv4 nft_compat
    nft_counter nft_chain_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 nf_tables nfnetlink bridge stp
    llc rpcsec_gss_krb5 auth_rpcgss nfsv4 dns_resolver nfs lockd grace fscache sunrpc intel_rapl_msr iTCO_wdt
    iTCO_vendor_support dell_smbios wmi_bmof dell_wmi_descriptor dcdbas kvm_intel kvm irqbypass
    intel_rapl_common isst_if_common skx_edac irdma nfit libnvdimm x86_pkg_temp_thermal i40e intel_powerclamp
    coretemp crct10dif_pclmul crc32_pclmul ghash_clmulni_intel ib_uverbs rapl ipmi_ssif intel_cstate
    intel_uncore mei_me pcspkr acpi_ipmi ib_core mei lpc_ich i2c_i801 ipmi_si ipmi_devintf wmi ipmi_msghandler
    acpi_power_meter xfs libcrc32c sd_mod t10_pi sg mgag200 drm_kms_helper syscopyarea sysfillrect sysimgblt
    fb_sys_fops ice ahci drm libahci crc32c_intel libata tg3 megaraid_sas [ 5119.170613] i2c_algo_bit
    dm_mirror dm_region_hash dm_log dm_mod fuse [last unloaded: iavf] [ 5119.170627] CR2: 00001b9780003237
    (CVE-2022-49722)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49722");

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
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "linux-aws-5.15",
     "linux-azure-5.15",
     "linux-azure-fde-5.15",
     "linux-gcp-5.15",
     "linux-hwe-5.15",
     "linux-ibm-5.15",
     "linux-intel-iotg-5.15",
     "linux-lowlatency-hwe-5.15",
     "linux-oracle-5.15",
     "linux-riscv-5.15"
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
