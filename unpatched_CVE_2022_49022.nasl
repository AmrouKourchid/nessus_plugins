#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225450);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49022");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49022");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: mac8021: fix possible oob access
    in ieee80211_get_rate_duration Fix possible out-of-bound access in ieee80211_get_rate_duration routine as
    reported by the following UBSAN report: UBSAN: array-index-out-of-bounds in net/mac80211/airtime.c:455:47
    index 15 is out of range for type 'u16 [12]' CPU: 2 PID: 217 Comm: kworker/u32:10 Not tainted
    6.1.0-060100rc3-generic Hardware name: Acer Aspire TC-281/Aspire TC-281, BIOS R01-A2 07/18/2017 Workqueue:
    mt76 mt76u_tx_status_data [mt76_usb] Call Trace: <TASK> show_stack+0x4e/0x61 dump_stack_lvl+0x4a/0x6f
    dump_stack+0x10/0x18 ubsan_epilogue+0x9/0x43 __ubsan_handle_out_of_bounds.cold+0x42/0x47
    ieee80211_get_rate_duration.constprop.0+0x22f/0x2a0 [mac80211] ? ieee80211_tx_status_ext+0x32e/0x640
    [mac80211] ieee80211_calc_rx_airtime+0xda/0x120 [mac80211] ieee80211_calc_tx_airtime+0xb4/0x100 [mac80211]
    mt76x02_send_tx_status+0x266/0x480 [mt76x02_lib] mt76x02_tx_status_data+0x52/0x80 [mt76x02_lib]
    mt76u_tx_status_data+0x67/0xd0 [mt76_usb] process_one_work+0x225/0x400 worker_thread+0x50/0x3e0 ?
    process_one_work+0x400/0x400 kthread+0xe9/0x110 ? kthread_complete_and_exit+0x20/0x20
    ret_from_fork+0x22/0x30 (CVE-2022-49022)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49022");

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
