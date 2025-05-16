#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214271);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/13");

  script_cve_id("CVE-2024-0135", "CVE-2024-0136", "CVE-2024-0137");
  script_xref(name:"IAVB", value:"2025-B-0007-S");

  script_name(english:"NVIDIA Container Toolkit 1.17.1 Multiple Vulnerabilities (2025_01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA Container Toolkit installed on the remote host is prior to 1.17.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the January 2025 advisory.

  - NVIDIA Container Toolkit contains an improper isolation vulnerability where a specially crafted container 
    image could lead to modification of a host binary. A successful exploit of this vulnerability may lead to 
    code execution, denial of service, escalation of privileges, information disclosure, and data tampering.
    (CVE-2024-0135)

  - NVIDIA Container Toolkit contains an improper isolation vulnerability where a specially crafted container 
    image could lead to untrusted code obtaining read and write access to host devices. This vulnerability is 
    present only when the NVIDIA Container Toolkit is configured in a nondefault way. A successful exploit of 
    this vulnerability may lead to code execution, denial of service, escalation of privileges, information 
    disclosure, and data tampering. (CVE-2024-0136)

  - NVIDIA Container Toolkit contains an improper isolation vulnerability where a specially crafted container 
    image could lead to untrusted code running in the host’s network namespace. This vulnerability is present 
    only when the NVIDIA Container Toolkit is configured in a nondefault way. A successful exploit of this 
    vulnerability may lead to denial of service and escalation of privileges. (CVE-2024-0137)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5599");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA Container Toolkit version 1.17.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-0136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:container_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_container_toolkit_nix_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Container Toolkit");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Container Toolkit');

var constraints = [
  { 'fixed_version' : '1.17.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
