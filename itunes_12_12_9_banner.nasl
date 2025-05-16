#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205760);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/19");

  script_cve_id("CVE-2023-32351", "CVE-2023-32353", "CVE-2023-32430");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2024-08-19");
  script_xref(name:"APPLE-SA", value:"HT213763");

  script_name(english:"Apple iTunes < 12.12.9 Multiple Vulnerabilities (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.12.9. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT213763 advisory.

  - A logic issue was addressed with improved checks. This issue is fixed in iTunes 12.12.9 for Windows. An
    app may be able to gain elevated privileges. (CVE-2023-32351)

  - A logic issue was addressed with improved checks. This issue is fixed in iTunes 12.12.9 for Windows. An
    app may be able to elevate privileges. (CVE-2023-32353)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213763");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.12.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32353");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("installed_sw/iTunes DAAP");
  script_require_ports("Services/www", 3689);

  exit(0);
}
include('http.inc');
include('vcf.inc');

var app = 'iTunes DAAP';
var port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

var app_info = vcf::get_app_info(app:app, port:port);
if (app_info.Type != 'Windows') audit(AUDIT_OS_NOT, 'Windows');
var constraints = [{'fixed_version':'12.12.9'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
