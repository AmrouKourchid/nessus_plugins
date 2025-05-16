#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229328);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41094");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41094");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/fbdev-dma: Only set smem_start is
    enable per module option Only export struct fb_info.fix.smem_start if that is required by the user and the
    memory does not come from vmalloc(). Setting struct fb_info.fix.smem_start breaks systems where DMA memory
    is backed by vmalloc address space. An example error is shown below. [ 3.536043] ------------[ cut here
    ]------------ [ 3.540716] virt_to_phys used for non-linear address: 000000007fc4f540 (0xffff800086001000)
    [ 3.552628] WARNING: CPU: 4 PID: 61 at arch/arm64/mm/physaddr.c:12 __virt_to_phys+0x68/0x98 [ 3.565455]
    Modules linked in: [ 3.568525] CPU: 4 PID: 61 Comm: kworker/u12:5 Not tainted
    6.6.23-06226-g4986cc3e1b75-dirty #250 [ 3.577310] Hardware name: NXP i.MX95 19X19 board (DT) [ 3.582452]
    Workqueue: events_unbound deferred_probe_work_func [ 3.588291] pstate: 60400009 (nZCv daif +PAN -UAO -TCO
    -DIT -SSBS BTYPE=--) [ 3.595233] pc : __virt_to_phys+0x68/0x98 [ 3.599246] lr : __virt_to_phys+0x68/0x98 [
    3.603276] sp : ffff800083603990 [ 3.677939] Call trace: [ 3.680393] __virt_to_phys+0x68/0x98 [ 3.684067]
    drm_fbdev_dma_helper_fb_probe+0x138/0x238 [ 3.689214]
    __drm_fb_helper_initial_config_and_unlock+0x2b0/0x4c0 [ 3.695385] drm_fb_helper_initial_config+0x4c/0x68 [
    3.700264] drm_fbdev_dma_client_hotplug+0x8c/0xe0 [ 3.705161] drm_client_register+0x60/0xb0 [ 3.709269]
    drm_fbdev_dma_setup+0x94/0x148 Additionally, DMA memory is assumed to by contiguous in physical address
    space, which is not guaranteed by vmalloc(). Resolve this by checking the module flag drm_leak_fbdev_smem
    when DRM allocated the instance of struct fb_info. Fbdev-dma then only sets smem_start only if required
    (via FBINFO_HIDE_SMEM_START). Also guarantee that the framebuffer is not located in vmalloc address space.
    (CVE-2024-41094)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41094");

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
