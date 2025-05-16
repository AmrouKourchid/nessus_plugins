#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228886);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41092");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41092");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/i915/gt: Fix potential UAF by
    revoke of fence registers CI has been sporadically reporting the following issue triggered by
    igt@i915_selftest@live@hangcheck on ADL-P and similar machines: <6> [414.049203] i915: Running
    intel_hangcheck_live_selftests/igt_reset_evict_fence ... <6> [414.068804] i915 0000:00:02.0: [drm] GT0:
    GUC: submission enabled <6> [414.068812] i915 0000:00:02.0: [drm] GT0: GUC: SLPC enabled <3> [414.070354]
    Unable to pin Y-tiled fence; err:-4 <3> [414.071282] i915_vma_revoke_fence:301
    GEM_BUG_ON(!i915_active_is_idle(&fence->active)) ... <4>[ 609.603992] ------------[ cut here ]------------
    <2>[ 609.603995] kernel BUG at drivers/gpu/drm/i915/gt/intel_ggtt_fencing.c:301! <4>[ 609.604003] invalid
    opcode: 0000 [#1] PREEMPT SMP NOPTI <4>[ 609.604006] CPU: 0 PID: 268 Comm: kworker/u64:3 Tainted: G U W
    6.9.0-CI_DRM_14785-g1ba62f8cea9c+ #1 <4>[ 609.604008] Hardware name: Intel Corporation Alder Lake Client
    Platform/AlderLake-P DDR4 RVP, BIOS RPLPFWI1.R00.4035.A00.2301200723 01/20/2023 <4>[ 609.604010]
    Workqueue: i915 __i915_gem_free_work [i915] <4>[ 609.604149] RIP: 0010:i915_vma_revoke_fence+0x187/0x1f0
    [i915] ... <4>[ 609.604271] Call Trace: <4>[ 609.604273] <TASK> ... <4>[ 609.604716]
    __i915_vma_evict+0x2e9/0x550 [i915] <4>[ 609.604852] __i915_vma_unbind+0x7c/0x160 [i915] <4>[ 609.604977]
    force_unbind+0x24/0xa0 [i915] <4>[ 609.605098] i915_vma_destroy+0x2f/0xa0 [i915] <4>[ 609.605210]
    __i915_gem_object_pages_fini+0x51/0x2f0 [i915] <4>[ 609.605330] __i915_gem_free_objects.isra.0+0x6a/0xc0
    [i915] <4>[ 609.605440] process_scheduled_works+0x351/0x690 ... In the past, there were similar failures
    reported by CI from other IGT tests, observed on other platforms. Before commit 63baf4f3d587
    (drm/i915/gt: Only wait for GPU activity before unbinding a GGTT fence), i915_vma_revoke_fence() was
    waiting for idleness of vma->active via fence_update(). That commit introduced vma->fence->active in order
    for the fence_update() to be able to wait selectively on that one instead of vma->active since only
    idleness of fence registers was needed. But then, another commit 0d86ee35097a (drm/i915/gt: Make fence
    revocation unequivocal) replaced the call to fence_update() in i915_vma_revoke_fence() with only
    fence_write(), and also added that GEM_BUG_ON(!i915_active_is_idle(&fence->active)) in front. No
    justification was provided on why we might then expect idleness of vma->fence->active without first
    waiting on it. The issue can be potentially caused by a race among revocation of fence registers on one
    side and sequential execution of signal callbacks invoked on completion of a request that was using them
    on the other, still processed in parallel to revocation of those fence registers. Fix it by waiting for
    idleness of vma->fence->active in i915_vma_revoke_fence(). (cherry picked from commit
    24bb052d3dd499c5956abad5f7d8e4fd07da7fb1) (CVE-2024-41092)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41092");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
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
