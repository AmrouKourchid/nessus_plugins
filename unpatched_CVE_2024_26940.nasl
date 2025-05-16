#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228076);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26940");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26940");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/vmwgfx: Create debugfs
    ttm_resource_manager entry only if needed The driver creates /sys/kernel/debug/dri/0/mob_ttm even when the
    corresponding ttm_resource_manager is not allocated. This leads to a crash when trying to read from this
    file. Add a check to create mob_ttm, system_mob_ttm, and gmr_ttm debug file only when the corresponding
    ttm_resource_manager is allocated. crash> bt PID: 3133409 TASK: ffff8fe4834a5000 CPU: 3 COMMAND: grep #0
    [ffffb954506b3b20] machine_kexec at ffffffffb2a6bec3 #1 [ffffb954506b3b78] __crash_kexec at
    ffffffffb2bb598a #2 [ffffb954506b3c38] crash_kexec at ffffffffb2bb68c1 #3 [ffffb954506b3c50] oops_end at
    ffffffffb2a2a9b1 #4 [ffffb954506b3c70] no_context at ffffffffb2a7e913 #5 [ffffb954506b3cc8]
    __bad_area_nosemaphore at ffffffffb2a7ec8c #6 [ffffb954506b3d10] do_page_fault at ffffffffb2a7f887 #7
    [ffffb954506b3d40] page_fault at ffffffffb360116e [exception RIP: ttm_resource_manager_debug+0x11] RIP:
    ffffffffc04afd11 RSP: ffffb954506b3df0 RFLAGS: 00010246 RAX: ffff8fe41a6d1200 RBX: 0000000000000000 RCX:
    0000000000000940 RDX: 0000000000000000 RSI: ffffffffc04b4338 RDI: 0000000000000000 RBP: ffffb954506b3e08
    R8: ffff8fee3ffad000 R9: 0000000000000000 R10: ffff8fe41a76a000 R11: 0000000000000001 R12:
    00000000ffffffff R13: 0000000000000001 R14: ffff8fe5bb6f3900 R15: ffff8fe41a6d1200 ORIG_RAX:
    ffffffffffffffff CS: 0010 SS: 0018 #8 [ffffb954506b3e00] ttm_resource_manager_show at ffffffffc04afde7
    [ttm] #9 [ffffb954506b3e30] seq_read at ffffffffb2d8f9f3 RIP: 00007f4c4eda8985 RSP: 00007ffdbba9e9f8
    RFLAGS: 00000246 RAX: ffffffffffffffda RBX: 000000000037e000 RCX: 00007f4c4eda8985 RDX: 000000000037e000
    RSI: 00007f4c41573000 RDI: 0000000000000003 RBP: 000000000037e000 R8: 0000000000000000 R9:
    000000000037fe30 R10: 0000000000000000 R11: 0000000000000246 R12: 00007f4c41573000 R13: 0000000000000003
    R14: 00007f4c41572010 R15: 0000000000000003 ORIG_RAX: 0000000000000000 CS: 0033 SS: 002b (CVE-2024-26940)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26940");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/01");
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
