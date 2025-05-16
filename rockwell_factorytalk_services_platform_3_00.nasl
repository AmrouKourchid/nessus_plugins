#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187749);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/22");

  script_cve_id("CVE-2018-18981");
  script_xref(name:"ICSA", value:"18-331-02");

  script_name(english:"Rockwell FactoryTalk Services Platform < 3.00 DoS");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rockwell FactoryTalk Services Platform installed on the remote Windows host is prior to 3.00. It is, therefore, affected by a
vulnerability.

  - A remote unauthenticated attacker could send numerous crafted packets to
    service ports resulting in memory consumption that could lead to a partial
    or complete denial-of-service condition to the affected services.
    (CVE-2018-18981)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-18-331-02");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rockwell FactoryTalk Services Platform version 3.00 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rockwellautomation:factorytalk_services_platform");
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
  { 'fixed_version' : '3.00' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
