#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209802);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2021-43081");

  script_name(english:"Fortinet Fortigate xss (FG-IR-21-230)");

  script_set_attribute(attribute:"synopsis", value:
"Remote host is affected by a xss vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-21-230 advisory.

  - An improper neutralization of input during web page generation vulnerability [CWE-79] in FortiOS version
    7.0.3 and below, 6.4.8 and below, 6.2.10 and below, 6.0.14 to 6.0.0. and in FortiProxy version 7.0.1 and
    below, 2.0.7 to 2.0.0 web filter override form may allow an unauthenticated attacker to perform an XSS
    attack via crafted HTTP GET requests. (CVE-2021-43081)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-230");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiOS version 6.2.11/6.4.9/7.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43081");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'min_version' : '6.0.0', 'max_version' : '6.0.14', 'fixed_version' : '6.2.11' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.10', 'fixed_version' : '6.2.11' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.8', 'fixed_version' : '6.4.9' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.3', 'fixed_version' : '7.0.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
