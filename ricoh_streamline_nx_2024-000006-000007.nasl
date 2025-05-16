#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200810);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/03");

  script_cve_id("CVE-2024-37124", "CVE-2024-37387");
  script_xref(name:"IAVB", value:"2024-B-0081");

  script_name(english:"Streamline NX Client Multiple Vulnerabilities (2024-000006, 2024-000007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Streamline NX Client installed on the remote host is prior to 3.2.1.19, 3.3.1.3, 3.3.2.201, 3.4.3.1,
3.5.1.201, 3.6.100.53, or 3.6.2.1. It is, therefore, affected by multiple vulnerabilities as referenced in the
2024-000006 and 2024-000007 advisories.

  - Use of potentially dangerous function issue exists in Ricoh Streamline NX PC Client. If this vulnerability
    is exploited, an attacker may create an arbitrary file in the PC where the product is installed.
    (CVE-2024-37124)

  - Use of potentially dangerous function issue exists in Ricoh Streamline NX PC Client. If this vulnerability
    is exploited, files in the PC where the product is installed may be altered. (CVE-2024-37387)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2024-000006
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b8f3322");
  # https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000077-2024-000006
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?907cfd6e");
  # https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2024-000007
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2e5e9ca");
  # https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000077-2024-000007
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f19eb90c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Streamline NX Client version 3.4.3.2, 3.5.1.202, 3.6.2.2, 3.7.2.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37124");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ricoh:streamline_nx_client_tool");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ricoh_streamline_nx_win_installed.nbin");
  script_require_keys("installed_sw/Streamline NX Client");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Streamline NX Client');

var constraints = [
  { 'equal' : '3.2.1.19',   'fixed_version' : '3.4.3.2'},
  { 'equal' : '3.3.1.3',    'fixed_version' : '3.4.3.2'},
  { 'equal' : '3.3.2.201',  'fixed_version' : '3.4.3.2'},
  { 'equal' : '3.4.3.1',    'fixed_version' : '3.4.3.2'},
  { 'equal' : '3.5.1.201',  'fixed_version' : '3.5.1.202'},
  { 'equal' : '3.6.2.1',    'fixed_version' : '3.6.2.2'},
  { 'equal' : '3.6.100.53', 'fixed_version' : '3.7.2.1'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);
