#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209662);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2024-45315", "CVE-2024-45316");
  script_xref(name:"IAVA", value:"2024-A-0664-S");

  script_name(english:"SonicWall Connect Tunnel Multiple Vulnerabilities (SNWLID-2024-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote installed SMA1000 Connect Tunnel client is vulnerable to a 
 number of vulnerabilities:

  - The Improper link resolution before file access ('Link Following') vulnerability in SonicWall Connect Tunnel 
    (version 12.4.3.271 and earlier of Windows client) allows users with standard privileges to create arbitrary 
    folders and files, potentially leading to local Denial of Service (DoS) attack. (CVE-2024-45315)

  - The Improper link resolution before file access ('Link Following') vulnerability in SonicWall Connect 
    Tunnel (version 12.4.3.271 and earlier of Windows client) allows users with standard privileges to delete arbitrary 
    folders and files, potentially leading to local privilege escalation attack. (CVE-2024-45316)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0017");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sonicwall:connect_tunnel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_connect_tunnel_installed.nbin");
  script_require_keys("installed_sw/Sonicwall Connect Tunnel");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Sonicwall Connect Tunnel', win_local:TRUE);


var constraints = [
  {'max_version': '12.4.3.271', 'fixed_version':'12.4.3.281'}
];

vcf::sonicwall_sonicos::check_version_and_report(
  app_info:app_info, 
  constraints:constraints,
  severity:SECURITY_HOLE);
