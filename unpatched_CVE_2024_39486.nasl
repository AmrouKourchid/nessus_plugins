#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228400);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-39486");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-39486");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/drm_file: Fix pid refcounting race
    <maarten.lankhorst@linux.intel.com>, Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann
    <tzimmermann@suse.de> filp->pid is supposed to be a refcounted pointer; however, before this patch,
    drm_file_update_pid() only increments the refcount of a struct pid after storing a pointer to it in
    filp->pid and dropping the dev->filelist_mutex, making the following race possible: process A process B
    ========= ========= begin drm_file_update_pid mutex_lock(&dev->filelist_mutex)
    rcu_replace_pointer(filp->pid, <pid B>, 1) mutex_unlock(&dev->filelist_mutex) begin drm_file_update_pid
    mutex_lock(&dev->filelist_mutex) rcu_replace_pointer(filp->pid, <pid A>, 1)
    mutex_unlock(&dev->filelist_mutex) get_pid(<pid A>) synchronize_rcu() put_pid(<pid B>) *** pid B reaches
    refcount 0 and is freed here *** get_pid(<pid B>) *** UAF *** synchronize_rcu() put_pid(<pid A>) As far as
    I know, this race can only occur with CONFIG_PREEMPT_RCU=y because it requires RCU to detect a quiescent
    state in code that is not explicitly calling into the scheduler. This race leads to use-after-free of a
    struct pid. It is probably somewhat hard to hit because process A has to pass through a
    synchronize_rcu() operation while process B is between mutex_unlock() and get_pid(). Fix it by ensuring
    that by the time a pointer to the current task's pid is stored in the file, an extra reference to the pid
    has been taken. This fix also removes the condition for synchronize_rcu(); I think that optimization is
    unnecessary complexity, since in that case we would usually have bailed out on the lockless check above.
    (CVE-2024-39486)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39486");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/06");
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
