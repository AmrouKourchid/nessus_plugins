#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226580);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52738");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52738");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu/fence: Fix oops due to non-
    matching drm_sched init/fini Currently amdgpu calls drm_sched_fini() from the fence driver sw fini routine
    - such function is expected to be called only after the respective init function - drm_sched_init() - was
    executed successfully. Happens that we faced a driver probe failure in the Steam Deck recently, and the
    function drm_sched_fini() was called even without its counter-part had been previously called, causing the
    following oops: amdgpu: probe of 0000:04:00.0 failed with error -110 BUG: kernel NULL pointer dereference,
    address: 0000000000000090 PGD 0 P4D 0 Oops: 0002 [#1] PREEMPT SMP NOPTI CPU: 0 PID: 609 Comm: systemd-
    udevd Not tainted 6.2.0-rc3-gpiccoli #338 Hardware name: Valve Jupiter/Jupiter, BIOS F7A0113 11/04/2022
    RIP: 0010:drm_sched_fini+0x84/0xa0 [gpu_sched] [...] Call Trace: <TASK>
    amdgpu_fence_driver_sw_fini+0xc8/0xd0 [amdgpu] amdgpu_device_fini_sw+0x2b/0x3b0 [amdgpu]
    amdgpu_driver_release_kms+0x16/0x30 [amdgpu] devm_drm_dev_init_release+0x49/0x70 [...] To prevent that,
    check if the drm_sched was properly initialized for a given ring before calling its fini counter-part.
    Notice ideally we'd use sched.ready for that; such field is set as the latest thing on drm_sched_init().
    But amdgpu seems to override the meaning of such field - in the above oops for example, it was a GFX
    ring causing the crash, and the sched.ready field was set to true in the ring init routine, regardless of
    the state of the DRM scheduler. Hence, we ended-up using sched.ops as per Christian's suggestion [0], and
    also removed the no_scheduler check [1]. [0] https://lore.kernel.org/amd-gfx/984ee981-2906-0eaf-
    ccec-9f80975cb136@amd.com/ [1] https://lore.kernel.org/amd-
    gfx/cd0e2994-f85f-d837-609f-7056d5fb7231@amd.com/ (CVE-2023-52738)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52738");

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
