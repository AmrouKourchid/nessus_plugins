#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192190);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/10");

  script_cve_id("CVE-2023-42938");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2024-03-14");
  script_xref(name:"APPLE-SA", value:"HT214091");

  script_name(english:"Apple iTunes < 12.13.1 A Vulnerability (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.13.1. It is, therefore, affected by a
vulnerability as referenced in the HT214091 advisory.

  - A logic issue was addressed with improved checks. This issue is fixed in iTunes 12.13.1 for Windows. A
    local attacker may be able to elevate their privileges. (CVE-2023-42938)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214091");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/18");

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
var constraints = [{'fixed_version':'12.13.1'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
