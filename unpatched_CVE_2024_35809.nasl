#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229318);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35809");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35809");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: PCI/PM: Drain runtime-idle callbacks
    before driver removal A race condition between the .runtime_idle() callback and the .remove() callback in
    the rtsx_pcr PCI driver leads to a kernel crash due to an unhandled page fault [1]. The problem is that
    rtsx_pci_runtime_idle() is not expected to be running after pm_runtime_get_sync() has been called, but the
    latter doesn't really guarantee that. It only guarantees that the suspend and resume callbacks will not be
    running when it returns. However, if a .runtime_idle() callback is already running when
    pm_runtime_get_sync() is called, the latter will notice that the runtime PM status of the device is
    RPM_ACTIVE and it will return right away without waiting for the former to complete. In fact, it cannot
    wait for .runtime_idle() to complete because it may be called from that callback (it arguably does not
    make much sense to do that, but it is not strictly prohibited). Thus in general, whoever is providing a
    .runtime_idle() callback needs to protect it from running in parallel with whatever code runs after
    pm_runtime_get_sync(). [Note that .runtime_idle() will not start after pm_runtime_get_sync() has returned,
    but it may continue running then if it has started earlier.] One way to address that race condition is to
    call pm_runtime_barrier() after pm_runtime_get_sync() (not before it, because a nonzero value of the
    runtime PM usage counter is necessary to prevent runtime PM callbacks from being invoked) to wait for the
    .runtime_idle() callback to complete should it be running at that point. A suitable place for doing that
    is in pci_device_remove() which calls pm_runtime_get_sync() before removing the driver, so it may as well
    call pm_runtime_barrier() subsequently, which will prevent the race in question from occurring, not just
    in the rtsx_pcr driver, but in any PCI drivers providing .runtime_idle() callbacks. (CVE-2024-35809)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35809");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/10");
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
