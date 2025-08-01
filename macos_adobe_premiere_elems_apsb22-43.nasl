##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164088);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2022-34235");
  script_xref(name:"IAVA", value:"2022-A-0322");

  script_name(english:"Adobe Premiere Elements Privilege Escalation (APSB22-43) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Premiere Elements instance installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Elements installed on the remote macOS host is prior to build 20.0
(20220702.Git.main.e4f8578). It is, therefore, affected by a vulnerability as referenced in the APSB22-43 advisory.

  - Adobe Premiere Elements version 2020v20 (and earlier) is affected by an Uncontrolled Search Path Element
    which could lead to Privilege Escalation. An attacker could leverage this vulnerability to obtain admin
    using an existing low-privileged user. Exploitation of this issue does not require user interaction.
    (CVE-2022-34235)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/premiere_elements/apsb22-43.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f527f74");
  script_set_attribute(attribute:"solution", value:
"Upgrade Adobe Premiere Elements to build 20.0 (20220702.Git.main.e4f8578) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_elements");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_elements_mac_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Premiere Elements");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Premiere Elements', win_local:FALSE);

# Need to pull the timestamp out of the build string
var build_version = app_info['Build Version'];
var match, timestamp;

if (!empty_or_null(build_version))
  match = pregmatch(pattern:"^([0-9]+)\..*\.[0-9a-f]+", string:build_version, icase:TRUE);

if (!empty_or_null(match) && !empty_or_null(match[1]))
  timestamp = match[1];

if (empty_or_null(timestamp))
  audit(AUDIT_UNKNOWN_BUILD, app_info['app'], app_info['version']);

if (
  app_info.version =~ "^20\.0" &&
  ver_compare(ver:timestamp, fix:'20220702', strict:FALSE) < 0
)
{
  app_info['display_version'] = app_info['version'] + ' ' + build_version;
  vcf::report_results(app_info:app_info, fix:'build 20.0 (20220702.Git.main.e4f8578)', severity:SECURITY_WARNING);
}
else
{
  vcf::audit(app_info);
}
