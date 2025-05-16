#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204780);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-29736", "CVE-2024-32007");
  script_xref(name:"IAVB", value:"2024-B-0096-S");

  script_name(english:"Apache CXF < 3.5.9, 3.6.x < 3.6.4, 4.0.x < 4.0.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Apache CXF is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache CXF installed on the remote Windows host is affected by multiple
vulnerabilities:

  - A SSRF vulnerability in WADL service description in versions of Apache CXF before 4.0.5, 3.6.4 and 3.5.9
    allows an attacker to perform SSRF style attacks on REST webservices. The attack only applies if a
    custom stylesheet parameter is configured. (CVE-2024-29736)

  - An improper input validation of the p2c parameter in the Apache CXF JOSE code before 4.0.5, 3.6.4 and 3.5.9 allows
    an attacker to perform a denial of service attack by specifying a large value for this parameter in a token. (CVE-2024-32007)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://cxf.apache.org/security-advisories.data/CVE-2024-29736.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?709f54d5");
  # https://cxf.apache.org/security-advisories.data/CVE-2024-32007.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcafe480");
  script_set_attribute(attribute:"solution", value:
"Update to Apache CXF 3.5.9, 3.6.4, 4.0.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:cxf");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_cxf_detect.nbin");
  script_require_keys("installed_sw/Apache CXF");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Apache CXF');

var constraints = [
  { 'fixed_version' : '3.5.9' },
  { 'min_version' : '3.6.0', 'fixed_version' : '3.6.4' },
  { 'min_version' : '4.0.0', 'fixed_version' : '4.0.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
