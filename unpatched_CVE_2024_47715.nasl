#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229268);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-47715");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-47715");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: mt76: mt7915: fix oops on non-
    dbdc mt7986 mt7915_band_config() sets band_idx = 1 on the main phy for mt7986 with MT7975_ONE_ADIE or
    MT7976_ONE_ADIE. Commit 0335c034e726 (wifi: mt76: fix race condition related to checking tx queue fill
    status) introduced a dereference of the phys array indirectly indexed by band_idx via wcid->phy_idx in
    mt76_wcid_cleanup(). This caused the following Oops on affected mt7986 devices: Unable to handle kernel
    read from unreadable memory at virtual address 0000000000000024 Mem abort info: ESR = 0x0000000096000005
    EC = 0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x05: level 1
    translation fault Data abort info: ISV = 0, ISS = 0x00000005 CM = 0, WnR = 0 user pgtable: 4k pages,
    39-bit VAs, pgdp=0000000042545000 [0000000000000024] pgd=0000000000000000, p4d=0000000000000000,
    pud=0000000000000000 Internal error: Oops: 0000000096000005 [#1] SMP Modules linked in: ... mt7915e
    mt76_connac_lib mt76 mac80211 cfg80211 ... CPU: 2 PID: 1631 Comm: hostapd Not tainted 5.15.150 #0 Hardware
    name: ZyXEL EX5700 (Telenor) (DT) pstate: 80400005 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc :
    mt76_wcid_cleanup+0x84/0x22c [mt76] lr : mt76_wcid_cleanup+0x64/0x22c [mt76] sp : ffffffc00a803700 x29:
    ffffffc00a803700 x28: ffffff80008f7300 x27: ffffff80003f3c00 x26: ffffff80000a7880 x25: ffffffc008c26e00
    x24: 0000000000000001 x23: ffffffc000a68114 x22: 0000000000000000 x21: ffffff8004172cc8 x20:
    ffffffc00a803748 x19: ffffff8004152020 x18: 0000000000000000 x17: 00000000000017c0 x16: ffffffc008ef5000
    x15: 0000000000000be0 x14: ffffff8004172e28 x13: ffffff8004172e28 x12: 0000000000000000 x11:
    0000000000000000 x10: ffffff8004172e30 x9 : ffffff8004172e28 x8 : 0000000000000000 x7 : ffffff8004156020
    x6 : 0000000000000000 x5 : 0000000000000031 x4 : 0000000000000000 x3 : 0000000000000001 x2 :
    0000000000000000 x1 : ffffff80008f7300 x0 : 0000000000000024 Call trace: mt76_wcid_cleanup+0x84/0x22c
    [mt76] __mt76_sta_remove+0x70/0xbc [mt76] mt76_sta_state+0x8c/0x1a4 [mt76]
    mt7915_eeprom_get_power_delta+0x11e4/0x23a0 [mt7915e] drv_sta_state+0x144/0x274 [mac80211]
    sta_info_move_state+0x1cc/0x2a4 [mac80211] sta_set_sinfo+0xaf8/0xc24 [mac80211]
    sta_info_destroy_addr_bss+0x4c/0x6c [mac80211] ieee80211_color_change_finish+0x1c08/0x1e70 [mac80211]
    cfg80211_check_station_change+0x1360/0x4710 [cfg80211] genl_family_rcv_msg_doit+0xb4/0x110
    genl_rcv_msg+0xd0/0x1bc netlink_rcv_skb+0x58/0x120 genl_rcv+0x34/0x50 netlink_unicast+0x1f0/0x2ec
    netlink_sendmsg+0x198/0x3d0 ____sys_sendmsg+0x1b0/0x210 ___sys_sendmsg+0x80/0xf0 __sys_sendmsg+0x44/0xa0
    __arm64_sys_sendmsg+0x20/0x30 invoke_syscall.constprop.0+0x4c/0xe0 do_el0_svc+0x40/0xd0 el0_svc+0x14/0x4c
    el0t_64_sync_handler+0x100/0x110 el0t_64_sync+0x15c/0x160 Code: d2800002 910092c0 52800023 f9800011
    (885f7c01) ---[ end trace 7e42dd9a39ed2281 ]--- Fix by using mt76_dev_phy() which will map band_idx to the
    correct phy for all hardware combinations. (CVE-2024-47715)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
     "linux-azure-cloud-tools-6.8.0-1007",
     "linux-azure-headers-6.8.0-1007",
     "linux-azure-tools-6.8.0-1007",
     "linux-buildinfo-6.8.0-1005-ibm",
     "linux-buildinfo-6.8.0-1007-azure",
     "linux-cloud-tools-6.8.0-1005-ibm",
     "linux-cloud-tools-6.8.0-1007-azure",
     "linux-headers-6.8.0-1005-ibm",
     "linux-headers-6.8.0-1007-azure",
     "linux-ibm-cloud-tools-6.8.0-1005",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-6.8.0-1005",
     "linux-ibm-source-6.8.0",
     "linux-ibm-tools-6.8.0-1005",
     "linux-ibm-tools-common",
     "linux-image-unsigned-6.8.0-1005-ibm",
     "linux-image-unsigned-6.8.0-1005-ibm-dbgsym",
     "linux-image-unsigned-6.8.0-1007-azure",
     "linux-image-unsigned-6.8.0-1007-azure-dbgsym",
     "linux-lowlatency-hwe-6.11",
     "linux-modules-6.8.0-1005-ibm",
     "linux-modules-6.8.0-1007-azure",
     "linux-modules-extra-6.8.0-1005-ibm",
     "linux-modules-extra-6.8.0-1007-azure",
     "linux-modules-iwlwifi-6.8.0-1005-ibm",
     "linux-modules-iwlwifi-6.8.0-1007-azure",
     "linux-raspi-realtime",
     "linux-realtime",
     "linux-tools-6.8.0-1005-ibm",
     "linux-tools-6.8.0-1007-azure",
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
     "linux-azure-6.8",
     "linux-hwe-6.8"
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
