#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229794);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47350");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47350");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: powerpc/mm: Fix lockup on kernel exec
    fault The powerpc kernel is not prepared to handle exec faults from kernel. Especially, the function
    is_exec_fault() will return 'false' when an exec fault is taken by kernel, because the check is based on
    reading current->thread.regs->trap which contains the trap from user. For instance, when provoking a LKDTM
    EXEC_USERSPACE test, current->thread.regs->trap is set to SYSCALL trap (0xc00), and the fault taken by the
    kernel is not seen as an exec fault by set_access_flags_filter(). Commit d7df2443cd5f (powerpc/mm: Fix
    spurious segfaults on radix with autonuma) made it clear and handled it properly. But later on commit
    d3ca587404b3 (powerpc/mm: Fix reporting of kernel execute faults) removed that handling, introducing
    test based on error_code. And here is the problem, because on the 603 all upper bits of SRR1 get cleared
    when the TLB instruction miss handler bails out to ISI. Until commit cbd7e6ca0210 (powerpc/fault: Avoid
    heavy search_exception_tables() verification), an exec fault from kernel at a userspace address was
    indirectly caught by the lack of entry for that address in the exception tables. But after that commit the
    kernel mainly relies on KUAP or on core mm handling to catch wrong user accesses. Here the access is not
    wrong, so mm handles it. It is a minor fault because PAGE_EXEC is not set, set_access_flags_filter()
    should set PAGE_EXEC and voila. But as is_exec_fault() returns false as explained in the beginning,
    set_access_flags_filter() bails out without setting PAGE_EXEC flag, which leads to a forever minor exec
    fault. As the kernel is not prepared to handle such exec faults, the thing to do is to fire in
    bad_kernel_fault() for any exec fault taken by the kernel, as it was prior to commit d3ca587404b3.
    (CVE-2021-47350)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47350");

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
       "match": {
        "os_version": "8"
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
