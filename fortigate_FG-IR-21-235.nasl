#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209738);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2022-22299");
  script_xref(name:"IAVA", value:"2022-A-0264-S");

  script_name(english:"Fortinet Fortigate Format string vulnerability in command line interpreter (FG-IR-21-235)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-21-235 advisory.

  - A format string vulnerability [CWE-134] in the command line interpreter of FortiADC version 6.0.0 through
    6.0.4, FortiADC version 6.1.0 through 6.1.5, FortiADC version 6.2.0 through 6.2.1, FortiProxy version
    1.0.0 through 1.0.7, FortiProxy version 1.1.0 through 1.1.6, FortiProxy version 1.2.0 through 1.2.13,
    FortiProxy version 2.0.0 through 2.0.7, FortiProxy version 7.0.0 through 7.0.1, FortiOS version 6.0.0
    through 6.0.14, FortiOS version 6.2.0 through 6.2.10, FortiOS version 6.4.0 through 6.4.8, FortiOS version
    7.0.0 through 7.0.2, FortiMail version 6.4.0 through 6.4.5, FortiMail version 7.0.0 through 7.0.2 may
    allow an authenticated user to execute unauthorized code or commands via specially crafted command
    arguments. (CVE-2022-22299)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-235");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiOS version 6.0.15/6.2.11/6.4.9/7.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22299");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '5.0.0', 'max_version' : '5.0.14', 'fixed_version' : '6.0.15' },
  { 'min_version' : '5.2.0', 'max_version' : '5.2.15', 'fixed_version' : '6.0.15' },
  { 'min_version' : '5.4.0', 'max_version' : '5.4.13', 'fixed_version' : '6.0.15' },
  { 'min_version' : '5.6.0', 'max_version' : '5.6.14', 'fixed_version' : '6.0.15' },
  { 'min_version' : '6.0.0', 'max_version' : '6.0.14', 'fixed_version' : '6.0.15' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.10', 'fixed_version' : '6.2.11' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.8', 'fixed_version' : '6.4.9' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.2', 'fixed_version' : '7.0.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
