#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228614);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-39501");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-39501");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drivers: core: synchronize
    really_probe() and dev_uevent() Synchronize the dev->driver usage in really_probe() and dev_uevent().
    These can run in different threads, what can result in the following race condition for dev->driver
    uninitialization: Thread #1: ========== really_probe() { ... probe_failed: ... device_unbind_cleanup(dev)
    { ... dev->driver = NULL; // <= Failed probe sets dev->driver to NULL ... } ... } Thread #2: ==========
    dev_uevent() { ... if (dev->driver) // If dev->driver is NULLed from really_probe() from here on, // after
    above check, the system crashes add_uevent_var(env, DRIVER=%s, dev->driver->name); ... } really_probe()
    holds the lock, already. So nothing needs to be done there. dev_uevent() is called with lock held, often,
    too. But not always. What implies that we can't add any locking in dev_uevent() itself. So fix this race
    by adding the lock to the non-protected path. This is the path where above race is observed:
    dev_uevent+0x235/0x380 uevent_show+0x10c/0x1f0 <= Add lock here dev_attr_show+0x3a/0xa0
    sysfs_kf_seq_show+0x17c/0x250 kernfs_seq_show+0x7c/0x90 seq_read_iter+0x2d7/0x940
    kernfs_fop_read_iter+0xc6/0x310 vfs_read+0x5bc/0x6b0 ksys_read+0xeb/0x1b0 __x64_sys_read+0x42/0x50
    x64_sys_call+0x27ad/0x2d30 do_syscall_64+0xcd/0x1d0 entry_SYSCALL_64_after_hwframe+0x77/0x7f Similar cases
    are reported by syzkaller in https://syzkaller.appspot.com/bug?extid=ffa8143439596313a85a But these are
    regarding the *initialization* of dev->driver dev->driver = drv; As this switches dev->driver to non-NULL
    these reports can be considered to be false-positives (which should be fixed by this commit, as well,
    though). The same issue was reported and tried to be fixed back in 2015 in
    https://lore.kernel.org/lkml/1421259054-2574-1-git-send-email-a.sangwan@samsung.com/ already.
    (CVE-2024-39501)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39501");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
