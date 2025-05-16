#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229133);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35909");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35909");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: wwan: t7xx: Split 64bit accesses
    to fix alignment issues Some of the registers are aligned on a 32bit boundary, causing alignment faults on
    64bit platforms. Unable to handle kernel paging request at virtual address ffffffc084a1d004 Mem abort
    info: ESR = 0x0000000096000061 EC = 0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW =
    0 FSC = 0x21: alignment fault Data abort info: ISV = 0, ISS = 0x00000061, ISS2 = 0x00000000 CM = 0, WnR =
    1, TnD = 0, TagAccess = 0 GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 swapper pgtable: 4k pages, 39-bit
    VAs, pgdp=0000000046ad6000 [ffffffc084a1d004] pgd=100000013ffff003, p4d=100000013ffff003,
    pud=100000013ffff003, pmd=0068000020a00711 Internal error: Oops: 0000000096000061 [#1] SMP Modules linked
    in: mtk_t7xx(+) qcserial pppoe ppp_async option nft_fib_inet nf_flow_table_inet mt7921u(O) mt7921s(O)
    mt7921e(O) mt7921_common(O) iwlmvm(O) iwldvm(O) usb_wwan rndis_host qmi_wwan pppox ppp_generic
    nft_reject_ipv6 nft_reject_ipv4 nft_reject_inet nft_reject nft_redir nft_quota nft_numgen nft_nat nft_masq
    nft_log nft_limit nft_hash nft_flow_offload nft_fib_ipv6 nft_fib_ipv4 nft_fib nft_ct nft_chain_nat
    nf_tables nf_nat nf_flow_table nf_conntrack mt7996e(O) mt792x_usb(O) mt792x_lib(O) mt7915e(O) mt76_usb(O)
    mt76_sdio(O) mt76_connac_lib(O) mt76(O) mac80211(O) iwlwifi(O) huawei_cdc_ncm cfg80211(O) cdc_ncm
    cdc_ether wwan usbserial usbnet slhc sfp rtc_pcf8563 nfnetlink nf_reject_ipv6 nf_reject_ipv4 nf_log_syslog
    nf_defrag_ipv6 nf_defrag_ipv4 mt6577_auxadc mdio_i2c libcrc32c compat(O) cdc_wdm cdc_acm at24
    crypto_safexcel pwm_fan i2c_gpio i2c_smbus industrialio i2c_algo_bit i2c_mux_reg i2c_mux_pca954x
    i2c_mux_pca9541 i2c_mux_gpio i2c_mux dummy oid_registry tun sha512_arm64 sha1_ce sha1_generic seqiv md5
    geniv des_generic libdes cbc authencesn authenc leds_gpio xhci_plat_hcd xhci_pci xhci_mtk_hcd xhci_hcd
    nvme nvme_core gpio_button_hotplug(O) dm_mirror dm_region_hash dm_log dm_crypt dm_mod dax usbcore
    usb_common ptp aquantia pps_core mii tpm encrypted_keys trusted CPU: 3 PID: 5266 Comm: kworker/u9:1
    Tainted: G O 6.6.22 #0 Hardware name: Bananapi BPI-R4 (DT) Workqueue: md_hk_wq t7xx_fsm_uninit [mtk_t7xx]
    pstate: 804000c5 (Nzcv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc :
    t7xx_cldma_hw_set_start_addr+0x1c/0x3c [mtk_t7xx] lr : t7xx_cldma_start+0xac/0x13c [mtk_t7xx] sp :
    ffffffc085d63d30 x29: ffffffc085d63d30 x28: 0000000000000000 x27: 0000000000000000 x26: 0000000000000000
    x25: ffffff80c804f2c0 x24: ffffff80ca196c05 x23: 0000000000000000 x22: ffffff80c814b9b8 x21:
    ffffff80c814b128 x20: 0000000000000001 x19: ffffff80c814b080 x18: 0000000000000014 x17: 0000000055c9806b
    x16: 000000007c5296d0 x15: 000000000f6bca68 x14: 00000000dbdbdce4 x13: 000000001aeaf72a x12:
    0000000000000001 x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000 x8 : ffffff80ca1ef6b4
    x7 : ffffff80c814b818 x6 : 0000000000000018 x5 : 0000000000000870 x4 : 0000000000000000 x3 :
    0000000000000000 x2 : 000000010a947000 x1 : ffffffc084a1d004 x0 : ffffffc084a1d004 Call trace:
    t7xx_cldma_hw_set_start_addr+0x1c/0x3c [mtk_t7xx] t7xx_fsm_uninit+0x578/0x5ec [mtk_t7xx]
    process_one_work+0x154/0x2a0 worker_thread+0x2ac/0x488 kthread+0xe0/0xec ret_from_fork+0x10/0x20 Code:
    f9400800 91001000 8b214001 d50332bf (f9000022) ---[ end trace 0000000000000000 ]--- The inclusion of
    io-64-nonatomic-lo-hi.h indicates that all 64bit accesses can be replaced by pairs of nonatomic 32bit
    access. Fix alignment by forcing all accesses to be 32bit on 64bit platforms. (CVE-2024-35909)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35909");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/19");
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
     "linux-buildinfo-5.15.0-1004-intel-iotg",
     "linux-cloud-tools-5.15.0-1004-intel-iotg",
     "linux-headers-5.15.0-1004-intel-iotg",
     "linux-image-unsigned-5.15.0-1004-intel-iotg",
     "linux-image-unsigned-5.15.0-1004-intel-iotg-dbgsym",
     "linux-intel-iot-realtime",
     "linux-intel-iotg-cloud-tools-5.15.0-1004",
     "linux-intel-iotg-cloud-tools-common",
     "linux-intel-iotg-headers-5.15.0-1004",
     "linux-intel-iotg-tools-5.15.0-1004",
     "linux-intel-iotg-tools-common",
     "linux-intel-iotg-tools-host",
     "linux-modules-5.15.0-1004-intel-iotg",
     "linux-modules-extra-5.15.0-1004-intel-iotg",
     "linux-tools-5.15.0-1004-intel-iotg"
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
    "name": "linux-intel-iotg-5.15",
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
