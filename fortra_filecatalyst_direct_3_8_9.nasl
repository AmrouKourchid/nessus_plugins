#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213326);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-25154");

  script_name(english:"Fortra FileCatalyst Direct Directory Traversal (CVE-2024-25154) (Version Check)");

  script_set_attribute(attribute:"synopsis", value:
"A web application is affected by a Directory Traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortra FileCatalyst Direct running on the remote
host is prior to 3.8.9. It is, therefore, is affected by a
number of vulnerabilities

- Improper URL validation allows path traversal in FileCatalyst Direct 3.8.8 and earlier allowing an encoded payload 
  to cause the web server to return files located outside of the webroot which may lead to data leakage. (CVE-2024-25154)

- FileCatalyst Direct 3.8.8 and earlier, the web server does not properly sanitize illegal characters in a URL which 
  is then embedded in a subsequent error page. A malicious actor could craft a URL which would then execute arbitrary 
  code within an HTML script tag. (CVE-2024-25155)

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortra.com/security/advisory/fi-2024-002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortra FileCatalyst Direct 3.8.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:fortra:filecatalyst_Direct");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortra_filecatalyst_direct_nix_installed.nbin");
  script_require_keys("installed_sw/Fortra FileCatalyst Direct Server");

  exit(0);
}

include('vcf.inc');
include('webapp_func.inc');

var app = 'Fortra FileCatalyst Direct Server';
var app_info = vcf::get_app_info(app:app);

var constraints = [
  {'min_version':'3.0.0', 'fixed_version':'3.8.9'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
