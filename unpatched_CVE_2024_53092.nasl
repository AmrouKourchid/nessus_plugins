#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231906);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53092");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53092");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: virtio_pci: Fix admin vq cleanup by
    using correct info pointer vp_modern_avq_cleanup() and vp_del_vqs() clean up admin vq resources by
    virtio_pci_vq_info pointer. The info pointer of admin vq is stored in vp_dev->admin_vq.info instead of
    vp_dev->vqs[]. Using the info pointer from vp_dev->vqs[] for admin vq causes a kernel NULL pointer
    dereference bug. In vp_modern_avq_cleanup() and vp_del_vqs(), get the info pointer from
    vp_dev->admin_vq.info for admin vq to clean up the resources. Also make info ptr as argument of
    vp_del_vq() to be symmetric with vp_setup_vq(). vp_reset calls vp_modern_avq_cleanup, and causes the Call
    Trace: ================================================================== BUG: kernel NULL pointer
    dereference, address:0000000000000000 ... CPU: 49 UID: 0 PID: 4439 Comm: modprobe Not tainted 6.11.0-rc5
    #1 RIP: 0010:vp_reset+0x57/0x90 [virtio_pci] Call Trace: <TASK> ... ? vp_reset+0x57/0x90 [virtio_pci] ?
    vp_reset+0x38/0x90 [virtio_pci] virtio_reset_device+0x1d/0x30 remove_vq_common+0x1c/0x1a0 [virtio_net]
    virtnet_remove+0xa1/0xc0 [virtio_net] virtio_dev_remove+0x46/0xa0 ... virtio_pci_driver_exit+0x14/0x810
    [virtio_pci] ================================================================== (CVE-2024-53092)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53092");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "24.04"
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
