#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226433);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52901");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52901");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: usb: xhci: Check endpoint is valid
    before dereferencing it When the host controller is not responding, all URBs queued to all endpoints need
    to be killed. This can cause a kernel panic if we dereference an invalid endpoint. Fix this by using
    xhci_get_virt_ep() helper to find the endpoint and checking if the endpoint is valid before dereferencing
    it. [233311.853271] xhci-hcd xhci-hcd.1.auto: xHCI host controller not responding, assume dead
    [233311.853393] Unable to handle kernel NULL pointer dereference at virtual address 00000000000000e8
    [233311.853964] pc : xhci_hc_died+0x10c/0x270 [233311.853971] lr : xhci_hc_died+0x1ac/0x270
    [233311.854077] Call trace: [233311.854085] xhci_hc_died+0x10c/0x270 [233311.854093]
    xhci_stop_endpoint_command_watchdog+0x100/0x1a4 [233311.854105] call_timer_fn+0x50/0x2d4 [233311.854112]
    expire_timers+0xac/0x2e4 [233311.854118] run_timer_softirq+0x300/0xabc [233311.854127]
    __do_softirq+0x148/0x528 [233311.854135] irq_exit+0x194/0x1a8 [233311.854143]
    __handle_domain_irq+0x164/0x1d0 [233311.854149] gic_handle_irq.22273+0x10c/0x188 [233311.854156]
    el1_irq+0xfc/0x1a8 [233311.854175] lpm_cpuidle_enter+0x25c/0x418 [msm_pm] [233311.854185]
    cpuidle_enter_state+0x1f0/0x764 [233311.854194] do_idle+0x594/0x6ac [233311.854201]
    cpu_startup_entry+0x7c/0x80 [233311.854209] secondary_start_kernel+0x170/0x198 (CVE-2023-52901)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
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
