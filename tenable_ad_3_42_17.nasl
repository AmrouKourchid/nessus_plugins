#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183963);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2023-23919",
    "CVE-2023-23920",
    "CVE-2023-23936",
    "CVE-2023-24807",
    "CVE-2023-30585",
    "CVE-2023-30588",
    "CVE-2023-30589",
    "CVE-2023-30590",
    "CVE-2023-38545",
    "CVE-2023-38546",
    "CVE-2023-44487",
    "CVE-2023-46118"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Tenable Identity Exposure < 3.42.17 Multiple Vulnerabilities (TNS-2023-33)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable Identity Exposure (formerly Tenable.ad) installed on the remote system is affected 
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Identity Exposure running on the remote host is prior to 3.42.17. 
It is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-33 advisory.
Tenable Identity Exposure leverages third-party software to help provide underlying functionality. Several of the
third-party components (RabbitMQ, libcurl, and nodeJS) were found to contain vulnerabilities, and updated versions 
have been made available by the providers. Out of caution and in line with best practice, Tenable has opted to 
upgrade these components to address the potential impact of the issues. Tenable Identity Exposure 3.42.17 updates 
RabbitMQ to version 3.12.6, libcurl to version 8.4.0 and nodeJS to version 18.18.0 to address the identified 
vulnerabilities. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-33");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/downloads/identity-exposure");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Identity Exposure 3.42.17 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:tenable_identity_exposure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:tenable_ad");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ad_win_installed.nbin", "tenable_ad_web_detect.nbin");
  script_require_keys("installed_sw/Tenable.ad");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable.ad';

var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'max_version' : '3.42.12', 'fixed_version' : '3.42.17' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
