#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212756);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id("CVE-2024-54131");
  script_xref(name:"IAVB", value:"2024-B-0194");

  script_name(english:"Kolide Agent for Windows >= 1.5.3 < 1.12.3 Privilege Escalation (CVE-2024-54131)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a Kolide Agent for Windows install that is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Kolide Agent for Windows installed on the remote host is greater or equal to 1.5.3 and prior to
1.12.3. It is, therefore, affected by a privilege escalation vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/kolide/launcher/security/advisories/GHSA-66q9-2rvx-qfj5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2118352");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kolide Agent for Windows 1.12.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54131");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:kolide:agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kolide_agent_win_installed.nbin");
  script_require_keys("installed_sw/Kolide Agent");

  exit(0);
}

include('vcf.inc');

var app_name = 'Kolide Agent';

var app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version':'1.5.3', 'fixed_version' : '1.12.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
