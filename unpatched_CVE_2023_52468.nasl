#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227199);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52468");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52468");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: class: fix use-after-free in
    class_register() The lock_class_key is still registered and can be found in lock_keys_hash hlist after
    subsys_private is freed in error handler path.A task who iterate over the lock_keys_hash later may cause
    use-after-free.So fix that up and unregister the lock_class_key before kfree(cp). On our platform, a
    driver fails to kset_register because of creating duplicate filename '/class/xxx'.With Kasan enabled, it
    prints a invalid-access bug report. KASAN bug report: BUG: KASAN: invalid-access in
    lockdep_register_key+0x19c/0x1bc Write of size 8 at addr 15ffff808b8c0368 by task modprobe/252 Pointer
    tag: [15], memory tag: [fe] CPU: 7 PID: 252 Comm: modprobe Tainted: G W 6.6.0-mainline-maybe-dirty #1 Call
    trace: dump_backtrace+0x1b0/0x1e4 show_stack+0x2c/0x40 dump_stack_lvl+0xac/0xe0 print_report+0x18c/0x4d8
    kasan_report+0xe8/0x148 __hwasan_store8_noabort+0x88/0x98 lockdep_register_key+0x19c/0x1bc
    class_register+0x94/0x1ec init_module+0xbc/0xf48 [rfkill] do_one_initcall+0x17c/0x72c
    do_init_module+0x19c/0x3f8 ... Memory state around the buggy address: ffffff808b8c0100: 8a 8a 8a 8a 8a 8a
    8a 8a 8a 8a 8a 8a 8a 8a 8a 8a ffffff808b8c0200: 8a 8a 8a 8a 8a 8a 8a 8a fe fe fe fe fe fe fe fe
    >ffffff808b8c0300: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe ^ ffffff808b8c0400: 03 03 03 03 03 03
    03 03 03 03 03 03 03 03 03 03 As CONFIG_KASAN_GENERIC is not set, Kasan reports invalid-access not use-
    after-free here.In this case, modprobe is manipulating the corrupted lock_keys_hash hlish where
    lock_class_key is already freed before. It's worth noting that this only can happen if lockdep is enabled,
    which is not true for normal system. (CVE-2023-52468)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/25");
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
