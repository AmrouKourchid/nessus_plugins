#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179480);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2022-40680");
  script_xref(name:"IAVA", value:"2022-A-0458-S");

  script_name(english:"Fortinet Fortigate xss (FG-IR-21-248)");

  script_set_attribute(attribute:"synopsis", value:
"Remote host is affected by a xss vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-21-248 advisory.

  - A improper neutralization of input during web page generation ('cross-site scripting') in Fortinet FortiOS
    6.0.7 - 6.0.15, 6.2.2 - 6.2.12, 6.4.0 - 6.4.9 and 7.0.0 - 7.0.3 allows a privileged attacker to execute
    unauthorized code or commands via storing malicious payloads in replacement messages. (CVE-2022-40680)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-248");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiProxy version 7.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40680");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.0.7', 'max_version' : '6.0.18', 'fixed_version' : '6.4.10' },
  { 'min_version' : '6.2.2', 'max_version' : '6.2.16', 'fixed_version' : '6.4.10' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.9', 'fixed_version' : '6.4.10' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.3', 'fixed_version' : '7.0.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
