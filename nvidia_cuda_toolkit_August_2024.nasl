#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206678);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2024-0109", "CVE-2024-0110", "CVE-2024-0111");
  script_xref(name:"IAVB", value:"2024-B-0127-S");

  script_name(english:"NVIDIA CUDA Toolkit < 12.6.68 (12.6U1) Multiple Vulnerabilities (August 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA CUDA Toolkit installed on the remote host is prior to 12.6.68 (12.6U1). It is, therefore, affected
by multiple vulnerabilities as referenced in the August 2024 advisory.

  - NVIDIA CUDA Toolkit contains a vulnerability in command `cuobjdump` where a user may cause a crash by
    passing in a malformed ELF file. A successful exploit of this vulnerability may cause an out of bounds
    read in the unprivileged process memory which could lead to a limited denial of service. (CVE-2024-0109)

  - NVIDIA CUDA Toolkit contains a vulnerability in command `cuobjdump` where a user may cause an out-of-bound
    write by passing in a malformed ELF file. A successful exploit of this vulnerability may lead to code
    execution or denial of service. (CVE-2024-0110)

  - NVIDIA CUDA Toolkit contains a vulnerability in command 'cuobjdump' where a user may cause a crash or
    produce incorrect output by passing a malformed ELF file. A successful exploit of this vulnerability may
    lead to a limited denial of service or data tampering. (CVE-2024-0111)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5564");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA CUDA Toolkit version 12.6.68 (12.6U1) or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0110");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:cuda_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_cuda_toolkit_win_installed.nbin");
  script_require_keys("installed_sw/NVIDIA CUDA Toolkit");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA CUDA Toolkit');

var constraints = [
  { 'fixed_version' : '12.6.68', 'fixed_display' : '12.6.68 (12.6U1)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
