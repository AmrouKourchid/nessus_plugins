#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200539);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id("CVE-2024-20355");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe95729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-saml-bypass-KkNvXyKW");

  script_name(english:"Cisco Firepower Threat Defense Software Authorization Bypass (cisco-sa-asaftd-saml-bypass-KkNvXyKW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the implementation of SAML 2.0 single sign-on (SSO) for remote access VPN services in Cisco 
Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an 
authenticated, remote attacker to successfully establish a VPN session on an affected device. This vulnerability
is due to improper separation of authorization domains when using SAML authentication. An attacker could exploit
this vulnerability by using valid credentials to successfully authenticate using their designated connection 
profile (tunnel group), intercepting the SAML SSO token that is sent back from the Cisco ASA device, and then 
submitting the same SAML SSO token to a different tunnel group for authentication. A successful exploit could 
allow the attacker to establish a remote access VPN session using a connection profile that they are not authorized
to use and connect to secured networks behind the affected device that they are not authorized to access. 
For successful exploitation, the attacker must have valid remote access VPN user credentials.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-saml-bypass-KkNvXyKW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d3efedf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe95729");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe95729");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20355");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
var model = product_info['model'];

var saml;
if (get_kb_item("Host/local_checks_enabled"))
{
  var buf = cisco_command_kb_item('Host/Cisco/Config/show_running-config_tunnel-group_count_authentication', 'show running-config tunnel-group | count authentication.*saml');
  if (check_cisco_result(buf))
  {
    var lines = split(buf, sep:'\n');
    foreach var line (lines)
    {
       var match = pregmatch(multiline:TRUE, pattern:"Number of lines which match regexp\s*=\s*([0-9]+)", string:line);
       if (!isnull(match))
       {
         saml = int(match[1]);
       }
    }
  }
}

if (isnull(saml)) 
  exit(0, "Enable credentials were not provided.");

if (saml < 2)
  audit(AUDIT_HOST_NOT, 'affected since SAML 2.0 not used for authentication');

var vuln_ranges;

if (model =~ "Secure.*31[0-9]{2}")
{
  vuln_ranges = [
    {'min_ver': '7.1.0', 'fix_ver': '7.2.4.1', 'fixed_display': '7.2.4.1 / 7.2.5'}
  ];
}
else if (model =~ "(FPR-?|Firepower)\s*(1[0-9]{3}|1K)")
{
  vuln_ranges = [
    {'min_ver': '6.6.0', 'fix_ver': '7.0.6'},
    {'min_ver': '7.1.0', 'fix_ver': '7.2.4.1', 'fixed_display': '7.2.4.1 / 7.2.5'}
  ];
}
else if (model =~ "ASA55[0-9]{2}-X")
{
  vuln_ranges = [
    {'min_ver': '6.2.3', 'fix_ver': '6.4.0.17'},
    {'min_ver': '6.6.0', 'fix_ver': '7.0.6'}
  ];
}
else 
{
  vuln_ranges = [
    {'min_ver': '6.2.3', 'fix_ver': '6.4.0.17'},
    {'min_ver': '6.6.0', 'fix_ver': '7.0.6'},
    {'min_ver': '7.1.0', 'fix_ver': '7.2.4.1', 'fixed_display': '7.2.4.1 / 7.2.5'}
  ];
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe95729'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

