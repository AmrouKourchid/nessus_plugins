#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228959);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36936");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36936");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: efi/unaccepted: touch soft lockup
    during memory accept Commit 50e782a86c98 (efi/unaccepted: Fix soft lockups caused by parallel memory
    acceptance) has released the spinlock so other CPUs can do memory acceptance in parallel and not triggers
    softlockup on other CPUs. However the softlock up was intermittent shown up if the memory of the TD guest
    is large, and the timeout of softlockup is set to 1 second: RIP: 0010:_raw_spin_unlock_irqrestore Call
    Trace: ? __hrtimer_run_queues <IRQ> ? hrtimer_interrupt ? watchdog_timer_fn ?
    __sysvec_apic_timer_interrupt ? __pfx_watchdog_timer_fn ? sysvec_apic_timer_interrupt </IRQ> ?
    __hrtimer_run_queues <TASK> ? hrtimer_interrupt ? asm_sysvec_apic_timer_interrupt ?
    _raw_spin_unlock_irqrestore ? __sysvec_apic_timer_interrupt ? sysvec_apic_timer_interrupt accept_memory
    try_to_accept_memory do_huge_pmd_anonymous_page get_page_from_freelist __handle_mm_fault __alloc_pages
    __folio_alloc ? __tdx_hypercall handle_mm_fault vma_alloc_folio do_user_addr_fault
    do_huge_pmd_anonymous_page exc_page_fault ? __do_huge_pmd_anonymous_page asm_exc_page_fault
    __handle_mm_fault When the local irq is enabled at the end of accept_memory(), the softlockup detects that
    the watchdog on single CPU has not been fed for a while. That is to say, even other CPUs will not be
    blocked by spinlock, the current CPU might be stunk with local irq disabled for a while, which hurts not
    only nmi watchdog but also softlockup. Chao Gao pointed out that the memory accept could be time costly
    and there was similar report before. Thus to avoid any softlocup detection during this stage, give the
    softlockup a flag to skip the timeout check at the end of accept_memory(), by invoking
    touch_softlockup_watchdog(). (CVE-2024-36936)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36936");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
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
