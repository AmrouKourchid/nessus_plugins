#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179955);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/01");

  script_cve_id(
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-1255",
    "CVE-2023-2650",
    "CVE-2023-3446",
    "CVE-2023-3817"
  );
  script_xref(name:"IAVA", value:"2023-A-0606-S");

  script_name(english:"Tenable Sensor Proxy < 1.0.8 Multiple Vulnerabilities (TNS-2023-28)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Sensor Proxy installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Sensor Proxy running on the remote host is version 1.0.7. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-28 advisory.

  - Sensor Proxy leverages third-party software to help provide underlying functionality. One of the third-
    party components (OpenSSL) was found to contain vulnerabilities, and updated versions have been made
    available by the provider. Out of caution and in line with best practice, Tenable has opted to upgrade
    these components to address the potential impact of the issues. Sensor Proxy 1.0.8 updates OpenSSL
    to version 3.0.10 to address the identified vulnerabilities. Tenable has released Sensor Proxy 1.0.8 to
    address these issues.   (CVE-2023-0465, CVE-2023-0466, CVE-2023-1255, CVE-2023-2650, 
    CVE-2023-3446, CVE-2023-3817)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/vulnerability-management/sensorproxy/Content/Welcome.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd232d64");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Sensor Proxy 1.0.8 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:sensorproxy");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sensorproxy_installed.nbin");
  script_require_ports("installed_sw/Tenable Sensor Proxy");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Tenable Sensor Proxy');

var constraints = [
  { 'equal' : '1.0.7', 'fixed_version' : '1.0.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
