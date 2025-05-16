#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209148);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/17");

  script_cve_id(
    "CVE-2024-47007",
    "CVE-2024-47008",
    "CVE-2024-47009",
    "CVE-2024-47010",
    "CVE-2024-47011"
  );
  script_xref(name:"TRA", value:"TRA-2024-42");

  script_name(english:"Ivanti Avalanche < 6.4.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise mobility management application is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Avalanche running on the remote host is prior
to 6.4.5. It is, therefore, is affected by multiple vulnerabilities :

  - A NULL pointer dereference in WLAvalancheService allows a remote
  unauthenticated attacker to crash the service. (CVE-2024-47007)

  - Server-side request forgery allows a remote unauthenticated
  attacker to leak sensitive information. (CVE-2024-47008)

  - Path Traversal allows a remote unauthenticated attacker to bypass
  authentication. (CVE-2024-47009, CVE-2024-47010)

  - Path Traversal allows a remote unauthenticated attacker to leak
  sensitive information. (CVE-2024-47011)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://forums.ivanti.com/s/article/Ivanti-Avalanche-6-4-5-Security-Advisory?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54b5c0d9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to v6.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47010");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:avalanche");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_avalanche_manager_detect.nbin");
  script_require_keys("installed_sw/Ivanti Avalanche Manager");

  exit(0);
}

include('vcf.inc');

var app = 'Ivanti Avalanche Manager';
var port = get_service(svc:'ivanti_avalanche_manager', default:1777);
var app_info = vcf::get_app_info(app:app, port:port);

var constraints = [
  {'fixed_version':'6.4.5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
