#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209734);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2021-32591");

  script_name(english:"Fortinet FortiWeb Multiple cryptographic flaws allow for full LDAP and RADIUS passwords compromise (FG-IR-20-222)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiWeb installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-20-222 advisory.

  - A missing cryptographic steps vulnerability in the function that encrypts users' LDAP and RADIUS
    credentials in FortiSandbox before 4.0.1, FortiWeb before 6.3.12, FortiADC before 6.2.1, FortiMail 7.0.1
    and earlier may allow an attacker in possession of the password store to compromise the confidentiality of
    the encrypted secrets. (CVE-2021-32591)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-20-222");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiWeb version 6.2.5/6.3.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32591");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_fortios.inc');

# Since there's a workaround specified in the advisory, we're making this require paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_name = 'FortiWeb';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '5.7.0', 'max_version' : '5.7.3', 'fixed_version' : '6.2.5' },
  { 'min_version' : '5.8.0', 'max_version' : '5.8.7', 'fixed_version' : '6.2.5' },
  { 'min_version' : '5.9.0', 'max_version' : '5.9.1', 'fixed_version' : '6.2.5' },
  { 'min_version' : '6.0.0', 'max_version' : '6.0.7', 'fixed_version' : '6.2.5' },
  { 'min_version' : '6.1.0', 'max_version' : '6.1.2', 'fixed_version' : '6.2.5' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.4', 'fixed_version' : '6.2.5' },
  { 'min_version' : '6.3.0', 'max_version' : '6.3.11', 'fixed_version' : '6.3.12' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);
