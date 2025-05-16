#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227957);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26870");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26870");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: NFSv4.2: fix nfs4_listxattr kernel BUG
    at mm/usercopy.c:102 A call to listxattr() with a buffer size = 0 returns the actual size of the buffer
    needed for a subsequent call. When size > 0, nfs4_listxattr() does not return an error because either
    generic_listxattr() or nfs4_listxattr_nfs4_label() consumes exactly all the bytes then size is 0 when
    calling nfs4_listxattr_nfs4_user() which then triggers the following kernel BUG: [ 99.403778] kernel BUG
    at mm/usercopy.c:102! [ 99.404063] Internal error: Oops - BUG: 00000000f2000800 [#1] SMP [ 99.408463] CPU:
    0 PID: 3310 Comm: python3 Not tainted 6.6.0-61.fc40.aarch64 #1 [ 99.415827] Call trace: [ 99.415985]
    usercopy_abort+0x70/0xa0 [ 99.416227] __check_heap_object+0x134/0x158 [ 99.416505]
    check_heap_object+0x150/0x188 [ 99.416696] __check_object_size.part.0+0x78/0x168 [ 99.416886]
    __check_object_size+0x28/0x40 [ 99.417078] listxattr+0x8c/0x120 [ 99.417252] path_listxattr+0x78/0xe0 [
    99.417476] __arm64_sys_listxattr+0x28/0x40 [ 99.417723] invoke_syscall+0x78/0x100 [ 99.417929]
    el0_svc_common.constprop.0+0x48/0xf0 [ 99.418186] do_el0_svc+0x24/0x38 [ 99.418376] el0_svc+0x3c/0x110 [
    99.418554] el0t_64_sync_handler+0x120/0x130 [ 99.418788] el0t_64_sync+0x194/0x198 [ 99.418994] Code:
    aa0003e3 d000a3e0 91310000 97f49bdb (d4210000) Issue is reproduced when generic_listxattr() returns
    'system.nfs4_acl', thus calling lisxattr() with size = 16 will trigger the bug. Add check on
    nfs4_listxattr() to return ERANGE error when it is called with size > 0 and the return value is greater
    than size. (CVE-2024-26870)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26870");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
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
