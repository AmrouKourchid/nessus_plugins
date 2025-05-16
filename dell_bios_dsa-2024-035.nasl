#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192946);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2024-0172");
  script_xref(name:"IAVA", value:"2024-A-0200");

  script_name(english:"Dell Client BIOS Privilege Escalation (DSA-2024-035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, therefore, affected by an contain an improper
privilege management security vulnerability. An unauthenticated local attacker could potentially exploit this
vulnerability, leading to privilege escalation

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000223727/dsa-2024-035-security-update-for-dell-poweredge-server-bios-for-an-improper-privilege-management-security-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80e0ed58");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:bios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_wmi.nbin");
  script_require_keys("BIOS/Model", "BIOS/Version", "BIOS/Vendor");

  exit(0);
}

include('vcf_extras.inc');

var app_name = 'Dell Inc.';
var app_info = vcf::dell_bios_win::get_app_info(app:app_name);
var model = app_info['model'];

var fix = '';
# Check model
if (model)
{
  if (model == 'PowerEdge R660') fix = '1.5.6';
  else if (model == 'PowerEdge R760') fix = '1.5.6';
  else if (model == 'PowerEdge C6620') fix = '1.5.6';
  else if (model == 'PowerEdge MX760c') fix = '1.5.6';
  else if (model == 'PowerEdge R860') fix = '1.5.6';
  else if (model == 'PowerEdge R960') fix = '1.5.6';
  else if (model == 'PowerEdge HS5610') fix = '1.5.6';
  else if (model == 'PowerEdge HS5620') fix = '1.5.6';
  else if (model == 'PowerEdge R660xs') fix = '1.5.6';
  else if (model == 'PowerEdge R760xs') fix = '1.5.6';
  else if (model == 'PowerEdge R760xd2') fix = '1.5.6';
  else if (model == 'PowerEdge T560') fix = '1.5.6';
  else if (model == 'PowerEdge R760xa') fix = '1.1.3';
  else if (model == 'PowerEdge XE9680') fix = '1.1.3';
  else if (model == 'PowerEdge XR5610') fix = '1.1.4';
  else if (model == 'PowerEdge XR8610t') fix = '1.1.3';
  else if (model == 'PowerEdge XR8620t') fix = '1.1.3';
  else if (model == 'PowerEdge XR7620') fix = '1.5.6';
  else if (model == 'PowerEdge XE8640') fix = '1.2.5';
  else if (model == 'PowerEdge XE9640') fix = '1.3.6';
  else if (model == 'PowerEdge R6615') fix = '1.4.6';
  else if (model == 'PowerEdge R7615') fix = '1.4.6';
  else if (model == 'PowerEdge R6625') fix = '1.4.6';
  else if (model == 'PowerEdge R7625') fix = '1.4.6';
  else if (model == 'PowerEdge R650') fix = '1.11.2';
  else if (model == 'PowerEdge R750') fix = '1.11.2';
  else if (model == 'PowerEdge R750xa') fix = '1.11.2';
  else if (model == 'PowerEdge C6520') fix = '1.11.2';
  else if (model == 'PowerEdge MX750c') fix = '1.11.2';
  else if (model == 'PowerEdge R550') fix = '1.11.2';
  else if (model == 'PowerEdge R450') fix = '1.11.2';
  else if (model == 'PowerEdge R650xs') fix = '1.11.2';
  else if (model == 'PowerEdge R750xs') fix = '1.11.2';
  else if (model == 'PowerEdge T550') fix = '1.11.2';
  else if (model == 'PowerEdge XR11') fix = '1.11.2';
  else if (model == 'PowerEdge XR12') fix = '1.11.2';
  else if (model == 'PowerEdge T150') fix = '1.7.3';
  else if (model == 'PowerEdge T350') fix = '1.7.3';
  else if (model == 'PowerEdge R250') fix = '1.7.3';
  else if (model == 'PowerEdge R350') fix = '1.7.3';
  else if (model == 'PowerEdge XR4510c') fix = '1.12.1';
  else if (model == 'PowerEdge XR4520c') fix = '1.12.1';
  else if (model == 'PowerEdge R6515') fix = '2.12.4';
  else if (model == 'PowerEdge R6525') fix = '2.12.4';
  else if (model == 'PowerEdge R7515') fix = '2.12.4';
  else if (model == 'PowerEdge R7525') fix = '2.12.4';
  else if (model == 'PowerEdge C6525') fix = '2.12.4';
  else if (model == 'PowerEdge XE8545') fix = '2.12.4';
  else if (model == 'PowerEdge R740') fix = '2.19.1';
  else if (model == 'PowerEdge R740xd') fix = '2.19.1';
  else if (model == 'PowerEdge R640') fix = '2.19.1';
  else if (model == 'PowerEdge R940') fix = '2.19.1';
  else if (model == 'PowerEdge R540') fix = '2.19.1';
  else if (model == 'PowerEdge R440') fix = '2.19.1';
  else if (model == 'PowerEdge T440') fix = '2.19.1';
  else if (model == 'PowerEdge XR2') fix = '2.19.1';
  else if (model == 'PowerEdge R740xd2') fix = '2.19.1';
  else if (model == 'PowerEdge R840') fix = '2.19.1';
  else if (model == 'PowerEdge R940XA') fix = '2.19.1';
  else if (model == 'PowerEdge T640') fix = '2.19.1';
  else if (model == 'PowerEdge C6420') fix = '2.19.1';
  else if (model == 'PowerEdge FC640') fix = '2.19.1';
  else if (model == 'PowerEdge M640') fix = '2.19.1';
  else if (model == 'PowerEdge M640 (VRTX)') fix = '2.19.1';
  else if (model == 'PowerEdge MX740c') fix = '2.19.1';
  else if (model == 'PowerEdge MX840c') fix = '2.19.1';
  else if (model == 'PowerEdge C4140') fix = '2.19.1';
  else if (model == 'DSS8440') fix = '2.19.0';
  else if (model == 'PowerEdge XE2420') fix = '2.19.0';
  else if (model == 'PowerEdge XE7420') fix = '2.19.0';
  else if (model == 'PowerEdge XE7440') fix = '2.19.0';
  else if (model == 'PowerEdge T140') fix = '2.14.1';
  else if (model == 'PowerEdge T340') fix = '2.14.1';
  else if (model == 'PowerEdge R240') fix = '2.14.1';
  else if (model == 'PowerEdge R340') fix = '2.14.1';
  else if (model == 'PowerEdge R6415') fix = '1.20.0';
  else if (model == 'PowerEdge R7415') fix = '1.20.0';
  else if (model == 'PowerEdge R7425') fix = '1.20.0';
  else if (model == 'Dell EMC NX3240') fix = '2.19.1';
  else if (model == 'Dell EMC NX3340') fix = '2.19.1';
  else if (model == 'Dell EMC NX440') fix = '2.14.1';
  else if (model == 'Dell EMC XC Core XC450') fix = '1.11.2';
  else if (model == 'Dell EMC XC Core XC650') fix = '1.11.2';
  else if (model == 'Dell EMC XC Core XC750') fix = '1.11.2';
  else if (model == 'Dell EMC XC Core XC750xa') fix = '1.11.2';
  else if (model == 'Dell EMC XC Core XC6520') fix = '1.11.2';
  else if (model == 'Dell EMC XC Core 6420 System') fix = '2.19.1';
  else if (model == 'Dell EMC XC Core XC640 System') fix = '2.19.1';
  else if (model == 'Dell EMC XC Core XC740xd System') fix = '2.19.1';
  else if (model == 'Dell EMC XC Core XC740xd2') fix = '2.19.1';
  else if (model == 'Dell EMC XC Core XC940 System') fix = '2.19.1';
  else if (model == 'Dell EMC XC Core XCXR2') fix = '2.19.1';
  else if (model == 'Dell EMC XC Core XC7525') fix = '2.12.4';
  else
  {
  audit(AUDIT_HOST_NOT, 'an affected model');
  }
}
else
{
  exit(0, 'The model of the device running the Dell BIOS could not be identified.');
}

var constraints = [{ 'fixed_version' : fix, 'fixed_display': fix + ' for ' + model }];
# Have a more useful audit message
app_info.app = 'Dell System BIOS for ' + model;

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
