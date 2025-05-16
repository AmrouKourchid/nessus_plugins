#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213168);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2023-38042", "CVE-2023-46810");

  script_name(english:"Ivanti Secure Access 22.x Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A VPN solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Ivanti Secure Access  installed on the remote host is 22.x. It is, therefore, affected by 
multiple vulnerabilities:

  - A local privilege escalation vulnerability in Ivanti Secure Access Client for Windows allows
    a low privileged user to execute code as SYSTEM. (CVE-2023-38042)

  - A local privilege escalation vulnerability in Ivanti Secure Access Client for Linux before 22.7R1, 
    allows a low privileged user to execute code as root. (CVE-2023-46810)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/KB-Security-Advisory-Ivanti-Secure-Access-Client-May-2024?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b927a28e");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ivanti:ivanti_secure_access_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("juniper_pulse_client_installed.nbin");
  script_require_keys("installed_sw/Ivanti Secure Access Client");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Ivanti Secure Access Client', win_local:TRUE);

var constraints = [
  {'fixed_version':'22.7.1.28369', 'fixed_display': '22.7R1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);