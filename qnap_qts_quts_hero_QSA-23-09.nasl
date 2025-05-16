#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180014);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id("CVE-2022-27600");

  script_name(english:"QNAP QTS / QuTS hero DoS (QSA-23-09)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS / QuTS hero installed on the remote host is affected by a denial of service vulnerability. A
remote attacker can exploit this issue to cause uncontrolled resource consumption resulting in a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-09");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-09 advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27600");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin", "qnap_quts_hero_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  { 'product' : 'QTS',                                'max_version' : '4.5.4', 'Number' : '2280', 'Build' : '20230112', 'fixed_display' : 'QTS 4.5.4.2280 build 20230112' },
  { 'product' : 'QTS',       'min_version' : '5.0.0', 'max_version' : '5.0.1', 'Number' : '2277', 'Build' : '20230112', 'fixed_display' : 'QTS 5.0.1.2277 build 20230112' },
  { 'product' : 'QuTS hero',                          'max_version' : '4.5.4', 'Number' : '2374', 'Build' : '20230417', 'fixed_display' : 'QuTS hero h4.5.4.2374 build 20230417' },
  { 'product' : 'QuTS hero', 'min_version' : '5.0.0', 'max_version' : '5.0.1', 'Number' : '2277', 'Build' : '20230112', 'fixed_display' : 'QuTS hero h5.0.1.2277 build 20230112' }
];
vcf::qnap::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
