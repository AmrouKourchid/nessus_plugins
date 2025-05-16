#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225171);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48868");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48868");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: dmaengine: idxd: Let probe fail when
    workqueue cannot be enabled The workqueue is enabled when the appropriate driver is loaded and disabled
    when the driver is removed. When the driver is removed it assumes that the workqueue was enabled
    successfully and proceeds to free allocations made during workqueue enabling. Failure during workqueue
    enabling does not prevent the driver from being loaded. This is because the error path within
    drv_enable_wq() returns success unless a second failure is encountered during the error path. By returning
    success it is possible to load the driver even if the workqueue cannot be enabled and allocations that do
    not exist are attempted to be freed during driver remove. Some examples of problematic flows: (a)
    idxd_dmaengine_drv_probe() -> drv_enable_wq() -> idxd_wq_request_irq(): In above flow, if
    idxd_wq_request_irq() fails then idxd_wq_unmap_portal() is called on error exit path, but drv_enable_wq()
    returns 0 because idxd_wq_disable() succeeds. The driver is thus loaded successfully.
    idxd_dmaengine_drv_remove()->drv_disable_wq()->idxd_wq_unmap_portal() Above flow on driver unload triggers
    the WARN in devm_iounmap() because the device resource has already been removed during error path of
    drv_enable_wq(). (b) idxd_dmaengine_drv_probe() -> drv_enable_wq() -> idxd_wq_request_irq(): In above
    flow, if idxd_wq_request_irq() fails then idxd_wq_init_percpu_ref() is never called to initialize the
    percpu counter, yet the driver loads successfully because drv_enable_wq() returns 0.
    idxd_dmaengine_drv_remove()->__idxd_wq_quiesce()->percpu_ref_kill(): Above flow on driver unload triggers
    a BUG when attempting to drop the initial ref of the uninitialized percpu ref: BUG: kernel NULL pointer
    dereference, address: 0000000000000010 Fix the drv_enable_wq() error path by returning the original error
    that indicates failure of workqueue enabling. This ensures that the probe fails when an error is
    encountered and the driver remove paths are only attempted when the workqueue was enabled successfully.
    (CVE-2022-48868)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
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
