#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227778);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26674");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26674");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: x86/lib: Revert to _ASM_EXTABLE_UA()
    for {get,put}_user() fixups During memory error injection test on kernels >= v6.4, the kernel panics like
    below. However, this issue couldn't be reproduced on kernels <= v6.3. mce: [Hardware Error]: CPU 296:
    Machine Check Exception: f Bank 1: bd80000000100134 mce: [Hardware Error]: RIP 10:<ffffffff821b9776>
    {__get_user_nocheck_4+0x6/0x20} mce: [Hardware Error]: TSC 411a93533ed ADDR 346a8730040 MISC 86 mce:
    [Hardware Error]: PROCESSOR 0:a06d0 TIME 1706000767 SOCKET 1 APIC 211 microcode 80001490 mce: [Hardware
    Error]: Run the above through 'mcelog --ascii' mce: [Hardware Error]: Machine check: Data load in
    unrecoverable area of kernel Kernel panic - not syncing: Fatal local machine check The MCA code can
    recover from an in-kernel #MC if the fixup type is EX_TYPE_UACCESS, explicitly indicating that the kernel
    is attempting to access userspace memory. However, if the fixup type is EX_TYPE_DEFAULT the only thing
    that is raised for an in-kernel #MC is a panic. ex_handler_uaccess() would warn if users gave a non-
    canonical addresses (with bit 63 clear) to {get, put}_user(), which was unexpected. Therefore, commit
    b19b74bc99b1 (x86/mm: Rework address range check in get_user() and put_user()) replaced
    _ASM_EXTABLE_UA() with _ASM_EXTABLE() for {get, put}_user() fixups. However, the new fixup type
    EX_TYPE_DEFAULT results in a panic. Commit 6014bc27561f (x86-64: make access_ok() independent of LAM)
    added the check gp_fault_address_ok() right before the WARN_ONCE() in ex_handler_uaccess() to not warn
    about non-canonical user addresses due to LAM. With that in place, revert back to _ASM_EXTABLE_UA() for
    {get,put}_user() exception fixups in order to be able to handle in-kernel MCEs correctly again. [ bp:
    Massage commit message. ] (CVE-2024-26674)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/02");
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
