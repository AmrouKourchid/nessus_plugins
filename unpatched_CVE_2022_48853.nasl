#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225166);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48853");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48853");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: swiotlb: fix info leak with
    DMA_FROM_DEVICE The problem I'm addressing was discovered by the LTP test covering cve-2018-1000204. A
    short description of what happens follows: 1) The test case issues a command code 00 (TEST UNIT READY) via
    the SG_IO interface with: dxfer_len == 524288, dxdfer_dir == SG_DXFER_FROM_DEV and a corresponding dxferp.
    The peculiar thing about this is that TUR is not reading from the device. 2) In sg_start_req() the
    invocation of blk_rq_map_user() effectively bounces the user-space buffer. As if the device was to
    transfer into it. Since commit a45b599ad808 (scsi: sg: allocate with __GFP_ZERO in sg_build_indirect())
    we make sure this first bounce buffer is allocated with GFP_ZERO. 3) For the rest of the story we keep
    ignoring that we have a TUR, so the device won't touch the buffer we prepare as if the we had a
    DMA_FROM_DEVICE type of situation. My setup uses a virtio-scsi device and the buffer allocated by SG is
    mapped by the function virtqueue_add_split() which uses DMA_FROM_DEVICE for the in sgs (here scatter-
    gather and not scsi generics). This mapping involves bouncing via the swiotlb (we need swiotlb to do
    virtio in protected guest like s390 Secure Execution, or AMD SEV). 4) When the SCSI TUR is done, we first
    copy back the content of the second (that is swiotlb) bounce buffer (which most likely contains some
    previous IO data), to the first bounce buffer, which contains all zeros. Then we copy back the content of
    the first bounce buffer to the user-space buffer. 5) The test case detects that the buffer, which it zero-
    initialized, ain't all zeros and fails. One can argue that this is an swiotlb problem, because without
    swiotlb we leak all zeros, and the swiotlb should be transparent in a sense that it does not affect the
    outcome (if all other participants are well behaved). Copying the content of the original buffer into the
    swiotlb buffer is the only way I can think of to make swiotlb transparent in such scenarios. So let's do
    just that if in doubt, but allow the driver to tell us that the whole mapped buffer is going to be
    overwritten, in which case we can preserve the old behavior and avoid the performance impact of the extra
    bounce. (CVE-2022-48853)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
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
