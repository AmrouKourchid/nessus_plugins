#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190555);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/22");

  script_cve_id("CVE-2023-47218", "CVE-2023-50358");

  script_name(english:"QNAP QTS / QuTS hero Multiple Vulnerabilities in QTS, QuTS hero (QSA-23-57)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS / QuTS hero installed on the remote host is affected by multiple vulnerabilities as referenced
in the QSA-23-57 advisory:

  - An OS command injection vulnerability has been reported to affect several QNAP operating system versions. If 
    exploited, the vulnerability could allow users to execute commands via a network. (CVE-2023-47218, CVE-2023-50358)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-57");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-57 advisory");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50358");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'QNAP QTS and QuTS Hero Unauthenticated Remote Code Execution in quick.cgi');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin", "qnap_quts_hero_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  { 'min_version' : '4.2.6', 'max_version' : '4.2.6', 'product' : 'QTS', 'fixed_display' : 'QTS 4.2.6 build 20240131', 'Build' : '20240131' },
  { 'min_version' : '4.3.3', 'max_version' : '4.3.3', 'product' : 'QTS', 'fixed_display' : 'QTS 4.3.3.2644 build 20240131', 'Number' : '2644', 'Build' : '20240131' },
  { 'min_version' : '4.3.4', 'max_version' : '4.3.4', 'product' : 'QTS', 'fixed_display' : 'QTS 4.3.4.2675 build 20240131', 'Number' : '2675', 'Build' : '20240131' },
  { 'min_version' : '4.3.5', 'max_version' : '4.3.6', 'product' : 'QTS', 'fixed_display' : 'QTS 4.3.6.2665 build 20240131', 'Number' : '2665', 'Build' : '20240131' },
  { 'min_version' : '4.4.0', 'max_version' : '4.5.4', 'product' : 'QTS', 'fixed_display' : 'QTS 4.5.4.2627 build 20231225', 'Number' : '2627', 'Build' : '20231225' },
  { 'min_version' : '5.0.0', 'max_version' : '5.0.0', 'product' : 'QTS', 'fixed_display' : 'QTS 5.0.0.1986 build 20220324', 'Number' : '1986', 'Build' : '20220324' },
  { 'min_version' : '5.0.1', 'max_version' : '5.0.1', 'product' : 'QTS', 'fixed_display' : 'QTS 5.0.1.2145 build 20220903', 'Number' : '2145', 'Build' : '20220903' },
  { 'min_version' : '5.1.0', 'max_version' : '5.1.0', 'product' : 'QTS', 'fixed_display' : 'QTS 5.1.0.2444 build 20230629', 'Number' : '2444', 'Build' : '20230629' },
  { 'min_version' : '5.1.5', 'max_version' : '5.1.5', 'product' : 'QTS', 'fixed_display' : 'QTS 5.1.5.2645 build 20240116', 'Number' : '2645', 'Build' : '20240116' },
  { 'min_version' : '4.5.4', 'max_version' : '4.5.4', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h4.5.4.1991 build 20220330', 'Number' : '1991', 'Build' : '20220330' },
  { 'min_version' : '5.0.0', 'max_version' : '5.0.0', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.0.0.1986 build 20220324', 'Number' : '1986', 'Build' : '20220324' },
  { 'min_version' : '5.0.1', 'max_version' : '5.0.1', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.0.1.2192 build 20221020', 'Number' : '2192', 'Build' : '20221020' },
  { 'min_version' : '5.1.0', 'max_version' : '5.1.0', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.1.0.2466 build 20230721', 'Number' : '2466', 'Build' : '20230721' },
  { 'min_version' : '5.1.5', 'max_version' : '5.1.5', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.1.5.2647 build 20240118', 'Number' : '2647', 'Build' : '20240118' }
];
vcf::qnap::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
