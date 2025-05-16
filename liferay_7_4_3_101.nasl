#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190929);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/29");

  script_cve_id("CVE-2023-47795");

  script_name(english:"Liferay Portal 7.4.x < 7.4.3.102 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Liferay Portal installed on the remote host is prior to 7.4.3.102. It is, therefore, affected by a
vulnerability as referenced in the advisory.

  - Stored cross-site scripting (XSS) vulnerability in the Document and Media widget in Liferay Portal
    7.4.3.18 through 7.4.3.101, and Liferay DXP 2023.Q3 before patch 6, and 7.4 update 18 through 92 allows
    remote authenticated users to inject arbitrary web script or HTML via a crafted payload injected into a
    document's Title text field. (CVE-2023-47795)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://liferay.dev/portal/security/known-vulnerabilities");
  script_set_attribute(attribute:"solution", value:
"Upgrade Liferay Portal based upon the guidance specified in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:liferay_portal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("installed_sw/KeePass");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'liferay_portal');

var constraints = [
  { 'min_version' : '7.4.3.18', 'fixed_version' : '7.4.3.102' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
