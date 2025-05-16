#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181454);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2016-0955",
    "CVE-2016-0956",
    "CVE-2016-0957",
    "CVE-2016-0958"
  );

  script_name(english:"Adobe Experience Manager 5.6.1, 6.0.0, and 6.1.0 Multiple Vulnerabilities (APSB16-05)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is either 5.6.1, 6.0.0, or 6.1.0. 
It is, therefore, affected by multiple vulnerabilities as referenced in the APSB16-05 advisory.

  - Adobe Experience Manager version 6.1 is affected by a cross-site scripting vulnerability that 
    could lead to information disclosure. Apply hot fix 8651 to resolve. (CVE-2016-0955)

  - Adobe Experience Manager version 5.6.1, 6.0, or 6.1 is affected by an information disclosure 
    vulnerability affecting Apache Sling Servlets Post 2.3.6 and earlier versions. Apply hot fix 6445
    to resolve. (CVE-2016-0956)

  - Adobe Experience Manager version 5.6.1, 6.0, or 6.1 is affected by a URL filter bypass vulnerability
    that could be used to circumvent dispatcher rules. Install Dispatcher 4.1.5 or higher to resolve. 
    (CVE-2016-0957)

  - Adobe Experience Manager version 5.6.1, 6.0, or 6.1 is affected by a Java deserialization issue. 
    Apply hot fix 8364 to resolve. (CVE-2016-0958)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb16-05.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43036e1a");
  script_set_attribute(attribute:"solution", value:
"Apply hot fixes 6445, 8651, 8364 and install Dispatcher 4.1.5 or upgrade to Adobe Experience Manager version 6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0958");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_experience_manager_http_detect.nbin", "adobe_experience_manager_installed.nbin");
  script_require_keys("installed_sw/Adobe Experience Manager");

  exit(0);
}

include('vcf.inc');

var app = 'Adobe Experience Manager';
var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { 'min_version' : '5.6.1', 'fixed_version' : '6.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
