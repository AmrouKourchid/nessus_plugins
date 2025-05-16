#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192116);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2023-48788");
  script_xref(name:"CEA-ID", value:"CEA-2024-0005");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/04/15");
  script_xref(name:"IAVA", value:"2024-A-0182-S");

  script_name(english:"Fortinet FortiClient EMS 7.0.x < 7.0.11 / 7.2.x < 7.2.3 (FG-IR-24-007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient EMS installed on the remote host is prior to 7.0.11 or 7.2.3. It is, therefore,
affected by a vulnerability as referenced in the FG-IR-24-007 advisory.

  - A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet
    FortiClientEMS version 7.2.0 through 7.2.2, FortiClientEMS 7.0.1 through 7.0.10 allows attacker to execute
    unauthorized code or commands via specially crafted packets. (CVE-2023-48788)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.fortinet.com/psirt/FG-IR-24-007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient EMS version 7.0.11 / 7.2.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'FortiNet FortiClient Endpoint Management Server FCTID SQLi to RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient_enterprise_management_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_forticlient_ems_win_installed.nbin", "fortinet_forticlient_ems_web_detect.nbin");
  script_require_keys("installed_sw/Fortinet FortiClient EMS");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Fortinet FortiClient EMS');

var constraints = [
  { 'min_version' : '7.0.1', 'fixed_version' : '7.0.11' },
  { 'min_version' : '7.2.0', 'fixed_version' : '7.2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
