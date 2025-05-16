#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189258);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2023-46290");
  script_xref(name:"ICSA", value:"23-299-06");
  script_xref(name:"IAVA", value:"2024-A-0317");

  script_name(english:"Rockwell FactoryTalk Services Platform 2.74 Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rockwell FactoryTalk Services Platform installed on the remote Windows host is 2.74. It is, therefore, affected by a
vulnerability.

  - Due to inadequate code logic, a previously unauthenticated threat actor
    could potentially obtain a local Windows OS user token through the
    FactoryTalk Services Platform web service and then use the token to log in
    into FactoryTalk Services Platform. This vulnerability can only be exploited
    if the authorized user did not previously log in into the FactoryTalk
    Services Platform web service. (CVE-2023-46290)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-23-299-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rockwell FactoryTalk Services Platform version 2.80 or later or refer to the vendor advisory for other mitigations.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46290");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/20");

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

# There are no versions between 2.74 and 2.80.
var constraints = [
  { 'min_version':'2.74', 'fixed_version' : '2.80' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
