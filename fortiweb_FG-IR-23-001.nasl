#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209852);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2023-25610");
  script_xref(name:"IAVA", value:"2023-A-0125-S");

  script_name(english:"Fortinet FortiWeb Heap buffer underflow in administrative interface (FG-IR-23-001)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiWeb installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-23-001 advisory.

  - A buffer underflow vulnerability in FortiOS & FortiProxy HTTP/HTTPS administrative interface could allow
    an unauthenticated, remote attacker to execute arbitrary code on the device and/or perform a DoS using
    specifically crafted requests. (CVE-2023-25610)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-001");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiOS version 6.0.17/6.2.13/6.4.12/7.0.10/7.2.4/7.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '6.1.0', 'max_version' : '6.1.3', 'fixed_version' : '6.1.4' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.7', 'fixed_version' : '6.2.8' },
  { 'min_version' : '6.3.0', 'max_version' : '6.3.22', 'fixed_version' : '6.3.23' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.2', 'fixed_version' : '6.4.3' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.6', 'fixed_version' : '7.0.7' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.1', 'fixed_version' : '7.2.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
