#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228686);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-38555");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-38555");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5: Discard command completions
    in internal error Fix use after free when FW completion arrives while device is in internal error state.
    Avoid calling completion handler in this case, since the device will flush the command interface and
    trigger all completions manually. Kernel log: ------------[ cut here ]------------ refcount_t: underflow;
    use-after-free. ... RIP: 0010:refcount_warn_saturate+0xd8/0xe0 ... Call Trace: <IRQ> ? __warn+0x79/0x120 ?
    refcount_warn_saturate+0xd8/0xe0 ? report_bug+0x17c/0x190 ? handle_bug+0x3c/0x60 ?
    exc_invalid_op+0x14/0x70 ? asm_exc_invalid_op+0x16/0x20 ? refcount_warn_saturate+0xd8/0xe0
    cmd_ent_put+0x13b/0x160 [mlx5_core] mlx5_cmd_comp_handler+0x5f9/0x670 [mlx5_core]
    cmd_comp_notifier+0x1f/0x30 [mlx5_core] notifier_call_chain+0x35/0xb0 atomic_notifier_call_chain+0x16/0x20
    mlx5_eq_async_int+0xf6/0x290 [mlx5_core] notifier_call_chain+0x35/0xb0
    atomic_notifier_call_chain+0x16/0x20 irq_int_handler+0x19/0x30 [mlx5_core]
    __handle_irq_event_percpu+0x4b/0x160 handle_irq_event+0x2e/0x80 handle_edge_irq+0x98/0x230
    __common_interrupt+0x3b/0xa0 common_interrupt+0x7b/0xa0 </IRQ> <TASK> asm_common_interrupt+0x22/0x40
    (CVE-2024-38555)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38555");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
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
