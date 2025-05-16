#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227850);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26939");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26939");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/i915/vma: Fix UAF on destroy
    against retire race Object debugging tools were sporadically reporting illegal attempts to free a still
    active i915 VMA object when parking a GT believed to be idle. [161.359441] ODEBUG: free active (active
    state 0) object: ffff88811643b958 object type: i915_active hint: __i915_vma_active+0x0/0x50 [i915]
    [161.360082] WARNING: CPU: 5 PID: 276 at lib/debugobjects.c:514 debug_print_object+0x80/0xb0 ...
    [161.360304] CPU: 5 PID: 276 Comm: kworker/5:2 Not tainted 6.5.0-rc1-CI_DRM_13375-g003f860e5577+ #1
    [161.360314] Hardware name: Intel Corporation Rocket Lake Client Platform/RocketLake S UDIMM 6L RVP, BIOS
    RKLSFWI1.R00.3173.A03.2204210138 04/21/2022 [161.360322] Workqueue: i915-unordered
    __intel_wakeref_put_work [i915] [161.360592] RIP: 0010:debug_print_object+0x80/0xb0 ... [161.361347]
    debug_object_free+0xeb/0x110 [161.361362] i915_active_fini+0x14/0x130 [i915] [161.361866]
    release_references+0xfe/0x1f0 [i915] [161.362543] i915_vma_parked+0x1db/0x380 [i915] [161.363129]
    __gt_park+0x121/0x230 [i915] [161.363515] ____intel_wakeref_put_last+0x1f/0x70 [i915] That has been
    tracked down to be happening when another thread is deactivating the VMA inside __active_retire() helper,
    after the VMA's active counter has been already decremented to 0, but before deactivation of the VMA's
    object is reported to the object debugging tool. We could prevent from that race by serializing
    i915_active_fini() with __active_retire() via ref->tree_lock, but that wouldn't stop the VMA from being
    used, e.g. from __i915_vma_retire() called at the end of __active_retire(), after that VMA has been
    already freed by a concurrent i915_vma_destroy() on return from the i915_active_fini(). Then, we should
    rather fix the issue at the VMA level, not in i915_active. Since __i915_vma_parked() is called from
    __gt_park() on last put of the GT's wakeref, the issue could be addressed by holding the GT wakeref long
    enough for __active_retire() to complete before that wakeref is released and the GT parked. I believe the
    issue was introduced by commit d93939730347 (drm/i915: Remove the vma refcount) which moved a call to
    i915_active_fini() from a dropped i915_vma_release(), called on last put of the removed VMA kref, to
    i915_vma_parked() processing path called on last put of a GT wakeref. However, its visibility to the
    object debugging tool was suppressed by a bug in i915_active that was fixed two weeks later with commit
    e92eb246feb9 (drm/i915/active: Fix missing debug object activation). A VMA associated with a request
    doesn't acquire a GT wakeref by itself. Instead, it depends on a wakeref held directly by the request's
    active intel_context for a GT associated with its VM, and indirectly on that intel_context's engine
    wakeref if the engine belongs to the same GT as the VMA's VM. Those wakerefs are released asynchronously
    to VMA deactivation. Fix the issue by getting a wakeref for the VMA's GT when activating it, and putting
    that wakeref only after the VMA is deactivated. However, exclude global GTT from that processing path,
    otherwise the GPU never goes idle. Since __i915_vma_retire() may be called from atomic contexts, use async
    variant of wakeref put. Also, to avoid circular locking dependency, take care of acquiring the wakeref
    before VM mutex when both are needed. v7: Add inline comments with justifications for: - using untracked
    variants of intel_gt_pm_get/put() (Nirmoy), - using async variant of _put(), - not getting the wakeref in
    case of a global GTT, - always getting the first wakeref outside vm->mutex. v6: Since
    __i915_vma_active/retire() callbacks are not serialized, storing a wakeref tracking handle inside struct
    i915_vma is not safe, and there is no other good place for that. Use untracked variants of
    intel_gt_pm_get/put_async(). v5: Replace tile with GT across commit description (Rodrigo), -
    ---truncated--- (CVE-2024-26939)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26939");

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
