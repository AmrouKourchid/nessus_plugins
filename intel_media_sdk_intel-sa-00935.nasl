#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197900);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/27");

  script_cve_id(
    "CVE-2023-48368",
    "CVE-2023-45221",
    "CVE-2023-22656",
    "CVE-2023-47282",
    "CVE-2023-47169"
  );
  script_xref(name:"IAVB", value:"2024-B-0064");

  script_name(english:"Intel Media SDK Multiple Vulnerabilities (INTEL-SA-00935)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Intel Media SDK installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Intel Media SDK installed on the remote host is affected by multiple vulnerabilities:

  - Improper input validation in Intel Media SDK software all versions may allow an authenticated user to potentially
    enable denial of service via local access. (CVE-2023-48368)

  - Improper buffer restrictions in Intel Media SDK all versions may allow an authenticated user to potentially enable
    escalation of privilege via local access. (CVE-2023-45221)
  
  - Out-of-bounds read in Intel Media SDK and some Intel oneVPL software before version 23.3.5 may allow an
    authenticated user to potentially enable escalation of privilege via local access. (CVE-2023-22656)

  - Out-of-bounds write in Intel Media SDK all versions and some Intel oneVPL software before version 23.3.5 may allow
    an authenticated user to potentially enable escalation of privilege via local access. (CVE-2023-47282)

  - Improper buffer restrictions in Intel Media SDK software all versions may allow an authenticated user to
    potentially enable denial of service via local access. (CVE-2023-47169)

Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00935.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8710b2e");
  script_set_attribute(attribute:"solution", value:
"Intel has issued a Product Discontinuation notice for Intel Media SDK software and recommends that users of the Intel
Media SDK software uninstall it or discontinue use at their earliest convenience.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48368");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-45221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:intel:media_sdk");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_media_sdk_linux_installed.nbin");
  script_require_keys("installed_sw/Intel Media SDK");

  exit(0);
}

include('vcf.inc');

var app = 'Intel Media SDK';
var app_info = vcf::get_app_info(app:app);

var constraints = [
  {'min_version':'0','fixed_display':'None'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
