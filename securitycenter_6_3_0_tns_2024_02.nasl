#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190549);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2023-7104", "CVE-2024-1367", "CVE-2024-1471");
  script_xref(name:"IAVA", value:"2024-A-0104-S");

  script_name(english:"Tenable Security Center < 6.3.0 Multiple Vulnerabilities (TNS-2024-02)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of SecurityCenter installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Security Center running on the remote host is prior to version 
6.3.0. It is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-02 advisory.

  - Security Center leverages third-party software to help provide underlying functionality. One of the third-
    party components (sqlite) was found to contain vulnerabilities, and updated versions have been made
    available by the providers. Out of caution and in line with best practice, Tenable has opted to upgrade
    these components to address the potential impact of the issues. Security Center 6.3.0 updates sqlite to
    version 3.44.0 to address the identified vulnerabilities. (CVE-2023-7104)

  - A command injection vulnerability exists where an authenticated, remote attacker with administrator 
    privileges on the Security Center application could modify Logging parameters, which could lead to 
    the execution of arbitrary code on the Security Center host. (CVE-2024-1367)

  - An HTML injection vulnerability exists where an authenticated, remote attacker with administrator 
    privileges on the Security Center application could modify Repository parameters, which could lead 
    to HTML redirection attacks. (CVE-2024-1471)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://docs.tenable.com/release-notes/Content/security-center/tenablesc.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0497814b");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-02");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Security Center 6.3.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1367");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-7104");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:security_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var constraints = [
  { 'fixed_version' : '6.3.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
