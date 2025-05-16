#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229546);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46755");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46755");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: mwifiex: Do not return unused
    priv in mwifiex_get_priv_by_id() mwifiex_get_priv_by_id() returns the priv pointer corresponding to the
    bss_num and bss_type, but without checking if the priv is actually currently in use. Unused priv pointers
    do not have a wiphy attached to them which can lead to NULL pointer dereferences further down the
    callstack. Fix this by returning only used priv pointers which have priv->bss_mode set to something else
    than NL80211_IFTYPE_UNSPECIFIED. Said NULL pointer dereference happened when an Accesspoint was started
    with wpa_supplicant -i mlan0 with this config: network={ ssid=somessid mode=2 frequency=2412
    key_mgmt=WPA-PSK WPA-PSK-SHA256 proto=RSN group=CCMP pairwise=CCMP psk=12345678 } When waiting for the
    AP to be established, interrupting wpa_supplicant with <ctrl-c> and starting it again this happens: |
    Unable to handle kernel NULL pointer dereference at virtual address 0000000000000140 | Mem abort info: |
    ESR = 0x0000000096000004 | EC = 0x25: DABT (current EL), IL = 32 bits | SET = 0, FnV = 0 | EA = 0, S1PTW =
    0 | FSC = 0x04: level 0 translation fault | Data abort info: | ISV = 0, ISS = 0x00000004, ISS2 =
    0x00000000 | CM = 0, WnR = 0, TnD = 0, TagAccess = 0 | GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 | user
    pgtable: 4k pages, 48-bit VAs, pgdp=0000000046d96000 | [0000000000000140] pgd=0000000000000000,
    p4d=0000000000000000 | Internal error: Oops: 0000000096000004 [#1] PREEMPT SMP | Modules linked in:
    caam_jr caamhash_desc spidev caamalg_desc crypto_engine authenc libdes mwifiex_sdio +mwifiex crct10dif_ce
    cdc_acm onboard_usb_hub fsl_imx8_ddr_perf imx8m_ddrc rtc_ds1307 lm75 rtc_snvs +imx_sdma caam
    imx8mm_thermal spi_imx error imx_cpufreq_dt fuse ip_tables x_tables ipv6 | CPU: 0 PID: 8 Comm: kworker/0:1
    Not tainted 6.9.0-00007-g937242013fce-dirty #18 | Hardware name: somemachine (DT) | Workqueue: events
    sdio_irq_work | pstate: 00000005 (nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) | pc :
    mwifiex_get_cfp+0xd8/0x15c [mwifiex] | lr : mwifiex_get_cfp+0x34/0x15c [mwifiex] | sp : ffff8000818b3a70 |
    x29: ffff8000818b3a70 x28: ffff000006bfd8a5 x27: 0000000000000004 | x26: 000000000000002c x25:
    0000000000001511 x24: 0000000002e86bc9 | x23: ffff000006bfd996 x22: 0000000000000004 x21: ffff000007bec000
    | x20: 000000000000002c x19: 0000000000000000 x18: 0000000000000000 | x17: 000000040044ffff x16:
    00500072b5503510 x15: ccc283740681e517 | x14: 0201000101006d15 x13: 0000000002e8ff43 x12: 002c01000000ffb1
    | x11: 0100000000000000 x10: 02e8ff43002c0100 x9 : 0000ffb100100157 | x8 : ffff000003d20000 x7 :
    00000000000002f1 x6 : 00000000ffffe124 | x5 : 0000000000000001 x4 : 0000000000000003 x3 : 0000000000000000
    | x2 : 0000000000000000 x1 : 0001000000011001 x0 : 0000000000000000 | Call trace: |
    mwifiex_get_cfp+0xd8/0x15c [mwifiex] | mwifiex_parse_single_response_buf+0x1d0/0x504 [mwifiex] |
    mwifiex_handle_event_ext_scan_report+0x19c/0x2f8 [mwifiex] | mwifiex_process_sta_event+0x298/0xf0c
    [mwifiex] | mwifiex_process_event+0x110/0x238 [mwifiex] | mwifiex_main_process+0x428/0xa44 [mwifiex] |
    mwifiex_sdio_interrupt+0x64/0x12c [mwifiex_sdio] | process_sdio_pending_irqs+0x64/0x1b8 |
    sdio_irq_work+0x4c/0x7c | process_one_work+0x148/0x2a0 | worker_thread+0x2fc/0x40c | kthread+0x110/0x114 |
    ret_from_fork+0x10/0x20 | Code: a94153f3 a8c37bfd d50323bf d65f03c0 (f940a000) | ---[ end trace
    0000000000000000 ]--- (CVE-2024-46755)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
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
    "name": "linux-azure-fde-5.15",
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
