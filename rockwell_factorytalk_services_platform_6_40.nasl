#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189991);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-21917");
  script_xref(name:"ICSA", value:"24-030-06");
  script_xref(name:"IAVA", value:"2024-A-0317");

  script_name(english:"Rockwell FactoryTalk Services Platform < 6.40 Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rockwell FactoryTalk Services Platform installed on the remote Windows host is prior to 6.40. It is, 
therefore, affected by a vulnerability.

  - A vulnerability exists in Rockwell Automation FactoryTalk® Service Platform
    that allows a malicious user to obtain the service token and use it for
    authentication on another FTSP directory. This is due to the lack of digital
    signing between the FTSP service token and directory.  If exploited, a
    malicious user could potentially retrieve user information and modify
    settings without any authentication. (CVE-2024-21917)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-24-030-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rockwell FactoryTalk Services Platform version 6.40 or later or refer to the vendor advisory for other mitigations.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21917");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rockwellautomation:factorytalk_services_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rockwell_factorytalk_services_platform_win_installed.nbin");
  script_require_keys("installed_sw/Rockwell FactoryTalk Services Platform");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Rockwell FactoryTalk Services Platform', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '6.40' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
