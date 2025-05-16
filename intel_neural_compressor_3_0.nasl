#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211955);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/29");

  script_cve_id(
    "CVE-2024-28028",
    "CVE-2024-36284",
    "CVE-2024-37181",
    "CVE-2024-39368",
    "CVE-2024-39766"
  );

  script_name(english:"Intel Neural Compressor < 3.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Intel Neural Compressor installed on the remote host is prior to 3.0. It is, therefore, affected by
the following:

  - Improper neutralization of special elements used in an SQL command ('SQL Injection') in some Intel Neural 
    Compressor software before version v3.0 may allow an authenticated user to potentially enable escalation of 
    privilege via adjacent access. (CVE-2024-39368)

  - Improper input validation in some Intel Neural Compressor software before version v3.0 may allow an 
    unauthenticated user to potentially enable escalation of privilege via adjacent access. (CVE-2024-28028)

  - Improper neutralization of special elements used in SQL command in some Intel Neural Compressor software before 
    version v3.0 may allow an authenticated user to potentially enable escalation of privilege via local access.
    (CVE-2024-39766)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01219.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?106bb4c4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Intel Neural Compressor version 3.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:neural_compressor");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_neural_compressor_detect.nbin");
  script_require_keys("installed_sw/neural-compressor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'neural-compressor');
var constraints = [
    {'fixed_version':'3.0' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

