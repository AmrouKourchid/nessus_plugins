#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190368);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_cve_id(
    "CVE-2023-41727",
    "CVE-2023-46216",
    "CVE-2023-46217",
    "CVE-2023-46220",
    "CVE-2023-46221",
    "CVE-2023-46222",
    "CVE-2023-46223",
    "CVE-2023-46224",
    "CVE-2023-46225",
    "CVE-2023-46257",
    "CVE-2023-46258",
    "CVE-2023-46259",
    "CVE-2023-46260",
    "CVE-2023-46261",
    "CVE-2023-46262",
    "CVE-2023-46263",
    "CVE-2021-22962",
    "CVE-2023-46264",
    "CVE-2023-46265",
    "CVE-2023-46266"
  );

  script_name(english:"Ivanti Avalanche < 6.4.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise mobility management application is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Avalanche running on the remote host is prior
to 6.4.2. It is, therefore, is affected by multiple vulnerabilities :

  - An attacker sending specially crafted data packets to the Mobile Device Server can cause memory corruption which 
    could result to a Denial of Service (DoS) or code execution. (CVE-2023-41727)

  - An attacker sending specially crafted data packets to the Mobile Device Server can cause memory corruption which 
  could result to a Denial of Service (DoS) or code execution. (CVE-2023-46216)

  - An attacker sending specially crafted data packets to the Mobile Device Server can cause memory corruption which 
  could result to a Denial of Service (DoS) or code execution. (CVE-2023-46217)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.ivanti.com/blog/new-ivanti-avalanche-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e02d094c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to v6.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46265");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

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
  {'fixed_version':'6.4.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);