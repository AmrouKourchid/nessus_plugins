#%NASL_MIN_LEVEL 80900
##
# Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234437);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2025-26645");

  script_name(english:"Remote Desktop client for Windows RCE (March 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by a remote-code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows Remote Desktop client for Windows installed on the remote host is missing security updates. It is, 
therefore, affected by a vulnerability. 

  - Relative path traversal in Remote Desktop Client allows an unauthorized attacker to execute code over a 
    network. (CVE-2025-26645)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2025-26645");
  # https://learn.microsoft.com/en-us/previous-versions/remote-desktop-client/whats-new-windows?tabs=windows-msrdc-msi#updates-for-version-126017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67be0d61");
  script_set_attribute(attribute:"solution", value:
"Upgrade to client version 1.2.6017, 1.2.6074 (Insider) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26645");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:remote_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("remote_desktop_installed.nbin");
  script_require_keys("installed_sw/Microsoft Remote Desktop");

  exit(0);
}

include('vcf.inc');

var appname = "Microsoft Remote Desktop";

var app_info = vcf::get_app_info(app:appname, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '1.2.6017' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
