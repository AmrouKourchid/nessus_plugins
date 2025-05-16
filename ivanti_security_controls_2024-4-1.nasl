#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213285);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/23");

  script_cve_id("CVE-2024-10251");
  script_xref(name:"IAVB", value:"2024-A-0833");

  script_name(english:"Ivanti Security Controls < 2024.4.1 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Security Controls instance running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Security Controls running on the remote host is prior to 2024.4.1. 
It is, therefore, affected by a local privilege escalation vulnerability where under specific circumstances, insecure permissions in 
Ivanti Security Controls before version 2024.4.1 could allow a local authenticated attacker 
to achieve local privilege escalation.

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Security-Controls-iSec-CVE-2024-10251?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da7066b5");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Security Controls 2024.4.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10251");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:security_controls");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_security_controls_detect_win.nbin");
  script_require_keys("installed_sw/Ivanti Security Controls");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Ivanti Security Controls');

var constraints = [
  { 'fixed_version':'9.6.9387.0', 'fixed_display': '2024.4.1 (GA 9.6.9387.0)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
