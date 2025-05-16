#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230143);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47349");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47349");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mwifiex: bring down link before
    deleting interface We can deadlock when rmmod'ing the driver or going through firmware reset, because the
    cfg80211_unregister_wdev() has to bring down the link for us, ... which then grab the same wiphy lock.
    nl80211_del_interface() already handles a very similar case, with a nice description: /* * We hold RTNL,
    so this is safe, without RTNL opencount cannot * reach 0, and thus the rdev cannot be deleted. * * We need
    to do it for the dev_close(), since that will call * the netdev notifiers, and we need to acquire the
    mutex there * but don't know if we get there from here or from some other * place (e.g. ip link set ...
    down). */ mutex_unlock(&rdev->wiphy.mtx); ... Do similarly for mwifiex teardown, by ensuring we bring the
    link down first. Sample deadlock trace: [ 247.103516] INFO: task rmmod:2119 blocked for more than 123
    seconds. [ 247.110630] Not tainted 5.12.4 #5 [ 247.115796] echo 0 >
    /proc/sys/kernel/hung_task_timeout_secs disables this message. [ 247.124557] task:rmmod state:D stack: 0
    pid: 2119 ppid: 2114 flags:0x00400208 [ 247.133905] Call trace: [ 247.136644] __switch_to+0x130/0x170 [
    247.140643] __schedule+0x714/0xa0c [ 247.144548] schedule_preempt_disabled+0x88/0xf4 [ 247.149714]
    __mutex_lock_common+0x43c/0x750 [ 247.154496] mutex_lock_nested+0x5c/0x68 [ 247.158884]
    cfg80211_netdev_notifier_call+0x280/0x4e0 [cfg80211] [ 247.165769] raw_notifier_call_chain+0x4c/0x78 [
    247.170742] call_netdevice_notifiers_info+0x68/0xa4 [ 247.176305] __dev_close_many+0x7c/0x138 [
    247.180693] dev_close_many+0x7c/0x10c [ 247.184893] unregister_netdevice_many+0xfc/0x654 [ 247.190158]
    unregister_netdevice_queue+0xb4/0xe0 [ 247.195424] _cfg80211_unregister_wdev+0xa4/0x204 [cfg80211] [
    247.201816] cfg80211_unregister_wdev+0x20/0x2c [cfg80211] [ 247.208016]
    mwifiex_del_virtual_intf+0xc8/0x188 [mwifiex] [ 247.214174] mwifiex_uninit_sw+0x158/0x1b0 [mwifiex] [
    247.219747] mwifiex_remove_card+0x38/0xa0 [mwifiex] [ 247.225316] mwifiex_pcie_remove+0xd0/0xe0
    [mwifiex_pcie] [ 247.231451] pci_device_remove+0x50/0xe0 [ 247.235849]
    device_release_driver_internal+0x110/0x1b0 [ 247.241701] driver_detach+0x5c/0x9c [ 247.245704]
    bus_remove_driver+0x84/0xb8 [ 247.250095] driver_unregister+0x3c/0x60 [ 247.254486]
    pci_unregister_driver+0x2c/0x90 [ 247.259267] cleanup_module+0x18/0xcdc [mwifiex_pcie] (CVE-2021-47349)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47349");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
