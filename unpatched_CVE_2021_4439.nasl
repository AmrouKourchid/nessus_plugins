#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224268);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-4439");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-4439");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: isdn: cpai: check ctr->cnr to avoid
    array index out of bound The cmtp_add_connection() would add a cmtp session to a controller and run a
    kernel thread to process cmtp. __module_get(THIS_MODULE); session->task = kthread_run(cmtp_session,
    session, kcmtpd_ctr_%d, session->num); During this process, the kernel thread would call
    detach_capi_ctr() to detach a register controller. if the controller was not attached yet,
    detach_capi_ctr() would trigger an array-index-out-bounds bug. [ 46.866069][ T6479] UBSAN: array-index-
    out-of-bounds in drivers/isdn/capi/kcapi.c:483:21 [ 46.867196][ T6479] index -1 is out of range for type
    'capi_ctr *[32]' [ 46.867982][ T6479] CPU: 1 PID: 6479 Comm: kcmtpd_ctr_0 Not tainted 5.15.0-rc2+ #8 [
    46.869002][ T6479] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014 [
    46.870107][ T6479] Call Trace: [ 46.870473][ T6479] dump_stack_lvl+0x57/0x7d [ 46.870974][ T6479]
    ubsan_epilogue+0x5/0x40 [ 46.871458][ T6479] __ubsan_handle_out_of_bounds.cold+0x43/0x48 [ 46.872135][
    T6479] detach_capi_ctr+0x64/0xc0 [ 46.872639][ T6479] cmtp_session+0x5c8/0x5d0 [ 46.873131][ T6479] ?
    __init_waitqueue_head+0x60/0x60 [ 46.873712][ T6479] ? cmtp_add_msgpart+0x120/0x120 [ 46.874256][ T6479]
    kthread+0x147/0x170 [ 46.874709][ T6479] ? set_kthread_struct+0x40/0x40 [ 46.875248][ T6479]
    ret_from_fork+0x1f/0x30 [ 46.875773][ T6479] (CVE-2021-4439)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4439");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/20");
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
