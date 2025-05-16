#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204969);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2024-6576");
  script_xref(name:"IAVA", value:"2024-A-0459");

  script_name(english:"Progress MOVEit Transfer < 2023.0.12 / 2023.1 < 2023.1.7 / 2024.0 < 2024.0.3 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"Improper Authentication vulnerability in Progress MOVEit Transfer (SFTP module) can lead to Privilege Escalation.This
issue affects MOVEit Transfer: from 2023.0.0 before 2023.0.12, from 2023.1.0 before 2023.1.7, from 2024.0.0 before
2024.0.3.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Product-Security-Alert-Bulletin-July-2024-CVE-2024-6576
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88065f55");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2023.0.12, 2023.1.7, 2024.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6576");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_transfer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_dmz_ftp_installed.nbin");

  exit(0);
}

include('vcf.inc');

var appname = 'Ipswitch MOVEit DMZ';
var app_info = vcf::get_app_info(app:appname);

var constraints = [
  { 'min_version': '15.0', 'fixed_version' : '15.0.12', 'fixed_display': '2023.0.12 (15.0.12)'},
  { 'min_version': '15.1', 'fixed_version' : '15.1.7', 'fixed_display': '2023.1.7 (15.1.7)'},
  { 'min_version': '16.0', 'fixed_version' : '16.0.3', 'fixed_display': '2024.0.3 (16.0.3)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
