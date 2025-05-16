#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201926);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/08");

  script_cve_id("CVE-2017-6195");

  script_name(english:"Progress MOVEit Transfer 2017 < 9.0.0.201, Ipswitch MOVEit DMZ < 8.2 / 8.2 < 8.2.0.20 / 8.3 < 8.3.0.30 SQL Injection (CVE-2017-6195)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Progress MOVEit Transfer, formerly Ipswitch MOVEit DMZ, installed on the remote host is affected by a
pre-authentication blind SQL injection vulnerability as referenced in Progress Community article 000192008.

  - Ipswitch MOVEit Transfer (formerly DMZ) allows pre-authentication blind SQL injection. The fixed versions are
    MOVEit Transfer 2017 9.0.0.201, MOVEit DMZ 8.3.0.30, and MOVEit DMZ 8.2.0.20.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Security-Vulnerability-Mar-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e3b57fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer 2017 version 9.0.0.201, or Ipswitch MOVEit DMZ 8.2.0.20 or 8.3.0.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_transfer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_dmz_ftp_installed.nbin");

  exit(0);
}

include('vcf.inc');

var appname = 'Ipswitch MOVEit DMZ';
var app_info = vcf::get_app_info(app:appname);

var constraints = [
  { 'fixed_version' : '8.2.0.20' },
  { 'min_version': '8.3', 'fixed_version' : '8.3.0.30' },
  { 'min_version': '9.0', 'fixed_version' : '9.0.0.201', 'fixed_display': '2017 (9.0.0.201)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
