#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225734);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48705");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48705");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: mt76: mt7921e: fix crash in chip
    reset fail In case of drv own fail in reset, we may need to run mac_reset several times. The sequence
    would trigger system crash as the log below. Because we do not re-enable/schedule tx_napi before disable
    it again, the process would keep waiting for state change in napi_diable(). To avoid the problem and keep
    status synchronize for each run, goto final resource handling if drv own failed. [ 5857.353423] mt7921e
    0000:3b:00.0: driver own failed [ 5858.433427] mt7921e 0000:3b:00.0: Timeout for driver own [ 5859.633430]
    mt7921e 0000:3b:00.0: driver own failed [ 5859.633444] ------------[ cut here ]------------ [ 5859.633446]
    WARNING: CPU: 6 at kernel/kthread.c:659 kthread_park+0x11d [ 5859.633717] Workqueue: mt76
    mt7921_mac_reset_work [mt7921_common] [ 5859.633728] RIP: 0010:kthread_park+0x11d/0x150 [ 5859.633736]
    RSP: 0018:ffff8881b676fc68 EFLAGS: 00010202 ...... [ 5859.633766] Call Trace: [ 5859.633768] <TASK> [
    5859.633771] mt7921e_mac_reset+0x176/0x6f0 [mt7921e] [ 5859.633778] mt7921_mac_reset_work+0x184/0x3a0
    [mt7921_common] [ 5859.633785] ? mt7921_mac_set_timing+0x520/0x520 [mt7921_common] [ 5859.633794] ?
    __kasan_check_read+0x11/0x20 [ 5859.633802] process_one_work+0x7ee/0x1320 [ 5859.633810]
    worker_thread+0x53c/0x1240 [ 5859.633818] kthread+0x2b8/0x370 [ 5859.633824] ?
    process_one_work+0x1320/0x1320 [ 5859.633828] ? kthread_complete_and_exit+0x30/0x30 [ 5859.633834]
    ret_from_fork+0x1f/0x30 [ 5859.633842] </TASK> (CVE-2022-48705)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/03");
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
