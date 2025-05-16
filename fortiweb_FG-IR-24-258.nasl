#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209711);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2024-6387");

  script_name(english:"Fortinet FortiWeb OpenSSH regreSSHion Attack (CVE-2024-6387) (FG-IR-24-258)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiWeb installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-24-258 advisory.

  - A race condition in sshd affecting versions between 8.5p1 and 9.7p1 (inclusive) may allow arbitrary code
    execution with root privileges. Successful exploitation has been demonstrated on 32-bit Linux/glibc
    systems with ASLR. According to OpenSSH, the attack has been tested under lab conditions and requires on
    average 6-8 hours of continuous connections up to the maximum the server will accept. Exploitation on
    64-bit systems is believed to be possible but has not been demonstrated at this time.  (CVE-2024-6387)

  - A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition
    which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be
    able to trigger it by failing to authenticate within a set time period. (CVE-2024-6387)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-24-258");
  script_set_attribute(attribute:"see_also", value:"https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-9.8");
  script_set_attribute(attribute:"see_also", value:"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387");
  script_set_attribute(attribute:"solution", value:
"For 7.2.x, upgrade to FortiWeb version 7.2.10 or later. For 7.4.x, upgrade to FortiWeb version 7.4.5 or later. For
7.6.x, upgrade to FortiWeb version 7.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6387");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '7.2.0', 'max_version' : '7.2.9', 'fixed_version' : '7.2.10' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.4', 'fixed_version' : '7.4.5' },
  { 'min_version' : '7.6.0', 'fixed_version' : '7.6.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
