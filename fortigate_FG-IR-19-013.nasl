#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209849);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2007-6750", "CVE-2019-17657");

  script_name(english:"Fortinet Fortigate Slow HTTP DoS Attacks Mitigation (FG-IR-19-013)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the FG-IR-19-013 advisory.

  - An Uncontrolled Resource Consumption vulnerability in Fortinet FortiSwitch below 3.6.11, 6.0.6 and 6.2.2,
    FortiAnalyzer below 6.2.3, FortiManager below 6.2.3 and FortiAP-S/W2 below 6.2.2 may allow an attacker to
    cause admin webUI denial of service (DoS) via handling special crafted HTTP requests/responses in pieces
    slowly, as demonstrated by Slow HTTP DoS Attacks. (CVE-2019-17657)

  - The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage)
    via partial HTTP requests, as demonstrated by Slowloris, related to the lack of the mod_reqtimeout module
    in versions before 2.2.15. (CVE-2007-6750)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-19-013");
  # https://blog.qualys.com/securitylabs/2011/11/02/how-to-protect-against-slow-http-attacks
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2764761");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiOS version 6.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
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

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.2.0', 'max_version' : '6.2.2', 'fixed_version' : '6.2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
