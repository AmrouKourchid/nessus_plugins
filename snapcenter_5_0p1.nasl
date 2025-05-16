#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208265);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2024-21993");
  script_xref(name:"IAVA", value:"2024-A-0584-S");

  script_name(english:"Netapp SnapCenter < 5.0p1 (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"NetApp SnapCenter running on the remote host is affected by an Information Disclosure Vulnerabiity");
  script_set_attribute(attribute:"description", value:
"The version of Netapp SnapCenter installed on the remote host is prior to the 5.0p1 release, It is therefore, affected
by a vulnerability referenced as CVE-2024-21993.

 - CVE-2024-21993 is a vulnerability that could allow an authenticated attacker to discover plain text credentials
   resulting in the disclsure of sensitive information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.netapp.com/advisory/ntap-20240705-0007/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SnapCenter version 5.0p1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21993");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netapp:snapcenter");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netapp_snapcenter_win_installed.nbin");
  script_require_keys("installed_sw/NetApp SnapCenter Server");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var app_info = vcf::get_app_info(app:'NetApp SnapCenter Server', win_local:1);

var constraints = [
  { 
    'max_version' : '5.0',
    'fixed_display': '5.0p1' 
  }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
