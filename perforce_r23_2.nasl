#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187212);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2023-35767",
    "CVE-2023-45319",
    "CVE-2023-45849",
    "CVE-2023-5759"
  );
  script_xref(name:"IAVA", value:"2023-A-0699");

  script_name(english:"Helix Core Server < 2023.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Helix Core Server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Helix Core Server running on the remote host is prior to 2023.2. It is, therefore, affected by multiple
vulnerabilities.

  - An arbitrary code execution which results in privilege escalation was discovered in Helix Core versions
    prior to 2023.2. (CVE-2023-45849)

  - In Helix Core versions prior to 2023.2, an unauthenticated remote Denial of Service (DoS) via the shutdown
    function was identified. (CVE-2023-35767)

  - In Helix Core versions prior to 2023.2, an unauthenticated remote Denial of Service (DoS) via the buffer
    was identified. (CVE-2023-5759)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.perforce.com/perforce/r23.2/user/relnotes.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Helix Core Server 2023.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:perforce:perforce_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("perforce_server_detect.nasl");
  script_require_keys("installed_sw/Helix Core Server");

  exit(0);
}

include('vcf.inc');

var app_name = 'Helix Core Server';

var port = get_service(svc:'perforce',
                   default:1666,
                   exit_on_fail:TRUE);

var app_info = vcf::get_app_info(app:app_name, port:port);

var constraints = [
  { 'fixed_version' : '2023.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
