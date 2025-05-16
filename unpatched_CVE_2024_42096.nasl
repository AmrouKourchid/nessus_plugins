#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228780);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42096");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42096");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: x86: stop playing stack games in
    profile_pc() The 'profile_pc()' function is used for timer-based profiling, which isn't really all that
    relevant any more to begin with, but it also ends up making assumptions based on the stack layout that
    aren't necessarily valid. Basically, the code tries to account the time spent in spinlocks to the caller
    rather than the spinlock, and while I support that as a concept, it's not worth the code complexity or the
    KASAN warnings when no serious profiling is done using timers anyway these days. And the code really does
    depend on stack layout that is only true in the simplest of cases. We've lost the comment at some point (I
    think when the 32-bit and 64-bit code was unified), but it used to say: Assume the lock function has
    either no stack frame or a copy of eflags from PUSHF. which explains why it just blindly loads a word or
    two straight off the stack pointer and then takes a minimal look at the values to just check if they might
    be eflags or the return pc: Eflags always has bits 22 and up cleared unlike kernel addresses but that
    basic stack layout assumption assumes that there isn't any lock debugging etc going on that would
    complicate the code and cause a stack frame. It causes KASAN unhappiness reported for years by syzkaller
    [1] and others [2]. With no real practical reason for this any more, just remove the code. Just for
    historical interest, here's some background commits relating to this code from 2006: 0cb91a229364 (i386:
    Account spinlocks to the caller during profiling for !FP kernels) 31679f38d886 (Simplify profile_pc on
    x86-64) and a code unification from 2009: ef4512882dbe (x86: time_32/64.c unify profile_pc) but the
    basics of this thing actually goes back to before the git tree. (CVE-2024-42096)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42096");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
