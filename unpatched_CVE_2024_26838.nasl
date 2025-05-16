#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228189);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26838");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26838");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RDMA/irdma: Fix KASAN issue with
    tasklet KASAN testing revealed the following issue assocated with freeing an IRQ. [50006.466686] Call
    Trace: [50006.466691] <IRQ> [50006.489538] dump_stack+0x5c/0x80 [50006.493475]
    print_address_description.constprop.6+0x1a/0x150 [50006.499872] ? irdma_sc_process_ceq+0x483/0x790 [irdma]
    [50006.505742] ? irdma_sc_process_ceq+0x483/0x790 [irdma] [50006.511644] kasan_report.cold.11+0x7f/0x118
    [50006.516572] ? irdma_sc_process_ceq+0x483/0x790 [irdma] [50006.522473] irdma_sc_process_ceq+0x483/0x790
    [irdma] [50006.528232] irdma_process_ceq+0xb2/0x400 [irdma] [50006.533601] ?
    irdma_hw_flush_wqes_callback+0x370/0x370 [irdma] [50006.540298] irdma_ceq_dpc+0x44/0x100 [irdma]
    [50006.545306] tasklet_action_common.isra.14+0x148/0x2c0 [50006.551096] __do_softirq+0x1d0/0xaf8
    [50006.555396] irq_exit_rcu+0x219/0x260 [50006.559670] irq_exit+0xa/0x20 [50006.563320]
    smp_apic_timer_interrupt+0x1bf/0x690 [50006.568645] apic_timer_interrupt+0xf/0x20 [50006.573341] </IRQ>
    The issue is that a tasklet could be pending on another core racing the delete of the irq. Fix by insuring
    any scheduled tasklet is killed after deleting the irq. (CVE-2024-26838)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26838");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
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
