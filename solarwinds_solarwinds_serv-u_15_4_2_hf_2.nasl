#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200179);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2024-28995");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/07");

  script_name(english:"SolarWinds Serv-U < 15.4.2 HF2");

  script_set_attribute(attribute:"synopsis", value:
"SolarWinds Serv-U is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Serv-U installed on the remote host is prior to 15.4.2 HF2. It is, therefore, affected by a
vulnerability as referenced in the solarwinds_serv-u_15_4_2_hf_2 advisory.

  - SolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read
    sensitive files on the host machine. (CVE-2024-28995)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28995
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73107af0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Serv-U version 15.4.2 HF2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28995");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u_file_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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
  { 'max_version' : '15.4.2 HF1', 'fixed_version' : '15.4.3', 'fixed_display' : '15.4.2 HF2' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    require_paranoia:TRUE,
    severity:SECURITY_HOLE
);
