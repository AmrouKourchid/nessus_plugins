#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190886);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/19");

  script_cve_id("CVE-2024-1708", "CVE-2024-1709");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/29");

  script_name(english:"ConnectWise ScreenConnect Service < 23.9.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A remote access server installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the ConnectWise ScreenConnect Service remote access software installed on the remote
Windows host is prior to 23.9.8. It is, therefore affected by multiple vulnerabilities:

  - A path-traversal vulnerability which may allow an attacker the ability to execute remote code or directly impact
    confidential data or critical systems. (CVE-2024-1708)

  - An Authentication Bypass Using an Alternate Path or Channel vulnerability which may allow an attacker direct
    access to confidential information or critical systems. (CVE-2024-1709)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b21e17eb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ConnectWise ScreenConnect Service version 23.9.8 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1709");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ConnectWise ScreenConnect Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:connectwise:screenconnect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("connectwise_screenconnect_win_installed.nbin");
  script_require_keys("installed_sw/ConnectWise ScreenConnect", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'ConnectWise ScreenConnect', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '23.9.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
