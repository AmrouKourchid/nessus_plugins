#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211473);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2024-22061",
    "CVE-2024-23526",
    "CVE-2024-23527",
    "CVE-2024-23528",
    "CVE-2024-23529",
    "CVE-2024-23530",
    "CVE-2024-23531",
    "CVE-2024-23532",
    "CVE-2024-23533",
    "CVE-2024-23534",
    "CVE-2024-23535",
    "CVE-2024-24991",
    "CVE-2024-24992",
    "CVE-2024-24993",
    "CVE-2024-24994",
    "CVE-2024-24995",
    "CVE-2024-24996",
    "CVE-2024-24997",
    "CVE-2024-24998",
    "CVE-2024-24999",
    "CVE-2024-25000",
    "CVE-2024-27975",
    "CVE-2024-27976",
    "CVE-2024-27977",
    "CVE-2024-27978",
    "CVE-2024-27984",
    "CVE-2024-29204"
  );

  script_name(english:"Ivanti Avalanche < 6.4.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise mobility management application is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Avalanche running on the remote host is prior
to 6.4.3. It is, therefore, is affected by multiple vulnerabilities :

  - A Heap overflow vulnerability in WLInfoRailService component of Ivanti 
    Avalanche before 6.4.3 allows an unauthenticated remote attacker to execute arbitrary commands. (CVE-2024-24996)

  - A Path Traversal vulnerability in web component of Ivanti Avalanche before 6.4.3 allows a remote 
    authenticated attacker to execute arbitrary commands as SYSTEM. (CVE-2024-24997)

  - An Unrestricted File-upload vulnerability in web component of Ivanti Avalanche before 6.4.3 allows a 
    remote authenticated attacker to execute arbitrary commands as SYSTEM. (CVE-2024-23534)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://forums.ivanti.com/s/article/Avalanche-6-4-3-Security-Hardening-and-CVEs-addressed?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4819c367");
  script_set_attribute(attribute:"solution", value:
"Upgrade to v6.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:avalanche");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_avalanche_manager_detect.nbin");
  script_require_keys("installed_sw/Ivanti Avalanche Manager");

  exit(0);
}

include('vcf.inc');

var app = 'Ivanti Avalanche Manager';
var port = get_service(svc:'ivanti_avalanche_manager', default:1777);
var app_info = vcf::get_app_info(app:app, port:port);

var constraints = [
  {'fixed_version':'6.4.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);