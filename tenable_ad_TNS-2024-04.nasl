#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191430);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-0057", "CVE-2024-20672");

  script_name(english:"Tenable Identity Exposure < 3.59.4 Multiple Vulnerabilities (TNS-2024-04)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Tenable Identity Exposure (formerly Tenable.ad) installed on the remote host is prior to 3.59.4. It is,
therefore, affected by multiple vulnerabilities in the bundled .NET core component as referenced in the TNS-2024-04
advisory.

  - .NET, .NET Framework, and Visual Studio Security Feature Bypass Vulnerability (CVE-2024-0057)

  - .NET Denial of Service Vulnerability (CVE-2024-20672)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2024-04");
  script_set_attribute(attribute:"solution", value:
"Upgrade Tenable.ad based upon the guidance specified in TNS-2024-04.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:tenable_identity_exposure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:tenable_ad");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ad_win_installed.nbin", "tenable_ad_web_detect.nbin");
  script_require_keys("installed_sw/Tenable.ad");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable.ad');

var constraints = [
  { 'max_version' : '3.42.17', 'fixed_version' : '3.59.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
