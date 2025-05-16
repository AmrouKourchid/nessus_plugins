#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201018);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-5806");
  script_xref(name:"IAVA", value:"2024-A-0372-S");

  script_name(english:"Progress MOVEit Transfer 2023.0.x < 2023.0.11 / 2023.1.x < 2023.1.6 / 2024.0.x < 2024.0.2 Authentication Bypass (June 2024)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Progress MOVEit Transfer, formerly Ipswitch MOVEit DMZ, installed on the remote host is affected by an
authentication bypass vulnerability as referenced in Progress Community article 000259290.

- Improper Authentication vulnerability in Progress MOVEit Transfer (SFTP module) can lead to Authentication Bypass
  in limited scenarios. This issue affects MOVEit Transfer: from 2023.0.0 before 2023.0.11, from 2023.1.0 before
  2023.1.6, from 2024.0.0 before 2024.0.2.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Product-Security-Alert-Bulletin-June-2024-CVE-2024-5806
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cba569ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2023.0.11, 2023.1.6, or 2024.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5806");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/26");

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
  { 'min_version': '15.0', 'fixed_version' : '15.0.11', 'fixed_display': '2023.0.11 (15.0.11)'},
  { 'min_version': '15.1', 'fixed_version' : '15.1.6', 'fixed_display': '2023.1.6 (15.1.6)'},
  { 'min_version': '16.0', 'fixed_version' : '16.0.2', 'fixed_display': '2024.0.2 (16.0.2)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
