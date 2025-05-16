#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208077);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id("CVE-2024-0132", "CVE-2024-0133");
  script_xref(name:"IAVB", value:"2024-B-0145");

  script_name(english:"NVIDIA Container Toolkit < 1.16.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA Container Toolkit installed on the remote host is prior to 1.16.2. It is, therefore, affected
by multiple vulnerabilities as referenced in the September 2024 Security Bulletin.

  - NVIDIA Container Toolkit 1.16.1 or earlier contains a Time-of-check Time-of-Use (TOCTOU) vulnerability 
  when used with default configuration where a specifically crafted container image may gain access to the
  host file system. This does not impact use cases where CDI is used. A successful exploit of this 
  vulnerability may lead to code execution, denial of service, escalation of privileges, information 
  disclosure, and data tampering. (CVE-2024-0132)

  - NVIDIA Container Toolkit 1.16.1 or earlier contains a vulnerability in the default mode of operation
  allowing a specially crafted container image to create empty files on the host file system. This does not
  impact use cases where CDI is used. A successful exploit of this vulnerability may lead to data tampering.
  (CVE-2024-0133)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5582");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA Container Toolkit version 1.16.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0132");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:container_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_container_toolkit_nix_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Container Toolkit");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Container Toolkit');

var constraints = [
  { 'fixed_version' : '1.16.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
