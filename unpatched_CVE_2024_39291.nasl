#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228870);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-39291");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-39291");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: Fix buffer size in
    gfx_v9_4_3_init_ cp_compute_microcode() and rlc_microcode() The function gfx_v9_4_3_init_microcode in
    gfx_v9_4_3.c was generating about potential truncation of output when using the snprintf function. The
    issue was due to the size of the buffer 'ucode_prefix' being too small to accommodate the maximum possible
    length of the string being written into it. The string being written is amdgpu/%s_mec.bin or
    amdgpu/%s_rlc.bin, where %s is replaced by the value of 'chip_name'. The length of this string without
    the %s is 16 characters. The warning message indicated that 'chip_name' could be up to 29 characters long,
    resulting in a total of 45 characters, which exceeds the buffer size of 30 characters. To resolve this
    issue, the size of the 'ucode_prefix' buffer has been reduced from 30 to 15. This ensures that the maximum
    possible length of the string being written into the buffer will not exceed its size, thus preventing
    potential buffer overflow and truncation issues. Fixes the below with gcc W=1:
    drivers/gpu/drm/amd/amdgpu/gfx_v9_4_3.c: In function gfx_v9_4_3_early_init':
    drivers/gpu/drm/amd/amdgpu/gfx_v9_4_3.c:379:52: warning: %s' directive output may be truncated writing up
    to 29 bytes into a region of size 23 [-Wformat-truncation=] 379 | snprintf(fw_name, sizeof(fw_name),
    amdgpu/%s_rlc.bin, chip_name); | ^~ ...... 439 | r = gfx_v9_4_3_init_rlc_microcode(adev, ucode_prefix);
    | ~~~~~~~~~~~~ drivers/gpu/drm/amd/amdgpu/gfx_v9_4_3.c:379:9: note: snprintf' output between 16 and 45
    bytes into a destination of size 30 379 | snprintf(fw_name, sizeof(fw_name), amdgpu/%s_rlc.bin,
    chip_name); | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    drivers/gpu/drm/amd/amdgpu/gfx_v9_4_3.c:413:52: warning: %s' directive output may be truncated writing up
    to 29 bytes into a region of size 23 [-Wformat-truncation=] 413 | snprintf(fw_name, sizeof(fw_name),
    amdgpu/%s_mec.bin, chip_name); | ^~ ...... 443 | r = gfx_v9_4_3_init_cp_compute_microcode(adev,
    ucode_prefix); | ~~~~~~~~~~~~ drivers/gpu/drm/amd/amdgpu/gfx_v9_4_3.c:413:9: note: snprintf' output
    between 16 and 45 bytes into a destination of size 30 413 | snprintf(fw_name, sizeof(fw_name),
    amdgpu/%s_mec.bin, chip_name); | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    (CVE-2024-39291)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/24");
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
