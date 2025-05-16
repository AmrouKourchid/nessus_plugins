#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186483);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/18");

  script_cve_id("CVE-2023-6217", "CVE-2023-6218");
  script_xref(name:"IAVA", value:"2023-A-0662-S");

  script_name(english:"Progress MOVEit Transfer < 2022.0.9 / 2022.1 < 2022.1.10 / 2023.0 < 2023.0.7 / 2023.1.1 Multiple Vulnerabilities (November 2023)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Progress MOVEit Transfer, formerly Ipswitch MOVEit DMZ, installed on the remote host is prior to
2022.0.9, 2022.1 prior to 2022.1.10, 2023.0 prior to 2023.0.7 or 2023.1.1. It is, therefore, affected by multiple
vulnerabilities as referenced in Progress Community article 000246898.

 - A privilege escalation path associated with group administrators has been identified.  It is possible
   for a group administrator to elevate a group members permissions to the role of an organization
   administrator. (CVE-2023-6218)

 - A reflected cross-site scripting (XSS) vulnerability has been identified when MOVEit Gateway is used in
   conjunction with MOVEit Transfer.  An attacker could craft a malicious payload targeting the system which
   comprises a MOVEit Gateway and MOVEit Transfer deployment. If a MOVEit user interacts with the crafted
   payload, the attacker would be able to execute malicious JavaScript within the context of the victim’s
   browser. (CVE-2023-6217)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Service-Pack-November-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48b26a03");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2022.0.9, 2022.1.10, 2023.0.7, 2023.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_transfer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_dmz_ftp_installed.nbin");

  exit(0);
}

include('vcf.inc');

var appname = 'Ipswitch MOVEit DMZ';
var app_info = vcf::get_app_info(app:appname);

var constraints = [
  { 'max_version': '13.1.99999999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '14.0', 'fixed_version' : '14.0.9', 'fixed_display': '2022.0.9 (14.0.9)'},
  { 'min_version': '14.1', 'fixed_version' : '14.1.10', 'fixed_display': '2022.1.10 (14.1.10)'},
  { 'min_version': '15.0', 'fixed_version' : '15.0.7', 'fixed_display': '2023.0.7 (15.0.7)'},
  { 'equal': '15.1.1', 'fixed_display': '2023.1.2 (15.1.2)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
