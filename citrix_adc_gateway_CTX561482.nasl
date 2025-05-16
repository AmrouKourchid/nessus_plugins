#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178442);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_cve_id("CVE-2023-3466", "CVE-2023-3467", "CVE-2023-3519");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/09");
  script_xref(name:"CEA-ID", value:"CEA-2023-0033");
  script_xref(name:"IAVA", value:"2023-A-0356-S");
  script_xref(name:"IAVA", value:"2023-A-0592");

  script_name(english:"Citrix ADC and Citrix Gateway Multiple Vulnerabilities (CTX561482)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix Gateway device is version 12.1, 13.0 before 13.0-91.13 or 13.1
before 13.1-49.13 or 13.1-FIPS before 13.1-37.159. It is therefore affected by multiple vulnerabilities:

  - An unauthenticated remote code execution affecting appliances configured as a Gateway (VPN virtual server, ICA
    Proxy, CVPN, RDP Proxy) or AAA virtual server. (CVE-2023-3519)

  - A reflected cross-site scripting vulnerability that requires victim to access an attacker-controlled link in the
    browser while being on a network with connectivity to the NSIP (CVE-2023-3466)

  - A Privilege Escalation to root administrator (nsroot) given authenticated access to NSIP or SNIP with management
    interface access (CVE-2023-3467)

Please refer to advisory CTX561482 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/article/CTX561482/citrix-adc-and-citrix-gateway-security-bulletin-for-cve20233519-cve20233466-cve20233467
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1405a57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 12.1-55.297-FIPS, 13.1-37.159-FIPS, 13.0-91.13, 13.1-49.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3519");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Citrix ADC (NetScaler) Forms SSO Target RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();
var constraints;

if (app_info['fips_status'] == 1)
{
  if (preg(pattern:"^12.1.*", string:app_info['version']))
    constraints = [ {'min_version': '12.1', 'fixed_version': '12.1.55.297', 'fixed_display': '12.1-55.297 and later releases of 12.1-FIPS.'} ];
  else if (preg(pattern:"^13.1.*", string:app_info['version']))
    constraints = [ {'min_version': '13.1', 'fixed_version': '13.1.37.159', 'fixed_display': '13.1-37.159 and later releases of 13.1-FIPS.'} ];
}
else
{
  constraints = [
  {'min_version': '12.1', 'fixed_version': '12.9999999', 'fixed_display': '12.1 is now End Of Life (EOL) and is vulnerable. Contact the vendor.'},
  {'min_version': '13.0', 'fixed_version': '13.0.91.13', 'fixed_display': '13.0-91.13'},
  {'min_version': '13.1', 'fixed_version': '13.1.49.13', 'fixed_display': '13.1-49.13'}
  ];
}

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  flags:{'xss':TRUE},
  severity:SECURITY_HOLE
);