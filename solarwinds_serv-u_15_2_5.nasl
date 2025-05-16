#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207863);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2021-35242", "CVE-2021-35245");

  script_name(english:"SolarWinds Serv-U 15.2.4 < 15.2.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"SolarWinds Serv-U is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Serv-U installed on the remote host is prior to 15.2.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the serv-u_15_2_5 advisory.

  - Serv-U server responds with valid CSRFToken when the request contains only Session. (CVE-2021-35242)

  - When a user has admin rights in Serv-U Console, the user can move, create and delete any files are able to
    be accessed on the Serv-U host machine. (CVE-2021-35245)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35242
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c670ecd");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35245
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08f5141c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U version 15.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35245");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-35242");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u_file_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("servu_version.nasl");
  script_require_keys("installed_sw/Serv-U");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('ftp_func.inc');

var port = get_ftp_port(default:21);

var app_info = vcf::get_app_info(app:'Serv-U', port:port);

var constraints = [
  { 'min_version' : '15.2.4', 'max_version' : '15.2.4 HF1', 'fixed_version' : '15.2.5' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
