#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190358);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_cve_id("CVE-2023-47561", "CVE-2023-47562");

  script_name(english:"QNAP Photo Station OS Command Injection (QSA-24-08)");

  script_set_attribute(attribute:"synopsis", value:
"A photo gallery application running on the remote NAS is affected by an OS command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Photo Station running on the remote QNAP NAS is affected by an OS command injection vulnerability. 
If exploited, the vulnerability could allow authenticated users to execute commands via a network.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-24-08");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:qnap:photo_station");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:photo_station");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_photostation_detect.nbin");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('vcf.inc');

var app = vcf::combined_get_app_info(app:'QNAP Photo Station');

var constraints = [{"fixed_version" : "6.4.2"}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE);
