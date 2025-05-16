#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181880);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/30");

  script_cve_id("CVE-2023-40043", "CVE-2023-42656", "CVE-2023-42660");
  script_xref(name:"IAVA", value:"2023-A-0501-S");

  script_name(english:"Progress MOVEit Transfer < 2021.1.8 / 2022.0 < 2022.0.8, 2022.1 < 2022.1.9 / 2023.0 < 2023.0.6 Multiple Vulnerabilities (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Progress MOVEit Transfer, formerly Ipswitch MOVEit DMZ, installed on the remote host is prior to
2021.1.8 / 2022.0 < 2022.0.8, 2022.1 < 2022.1.9 / 2023.0 < 2023.0.6. It is, therefore, affected by multiple
vulnerabilities as referenced in Progress Community article 000241629.

  - In Progress MOVEit Transfer versions released before 2021.1.8 (13.1.8), 2022.0.8 (14.0.8), 2022.1.9
    (14.1.9), 2023.0.6 (15.0.6), a SQL injection vulnerability has been identified in the MOVEit Transfer web
    interface that could allow a MOVEit system administrator account to gain unauthorized access to the MOVEit
    Transfer database. A MOVEit system administrator could submit a crafted payload to the MOVEit Transfer web
    interface which could result in modification and disclosure of MOVEit database content. (CVE-2023-40043)

  - In Progress MOVEit Transfer versions released before 2021.1.8 (13.1.8), 2022.0.8 (14.0.8), 2022.1.9
    (14.1.9), 2023.0.6 (15.0.6), a reflected cross-site scripting (XSS) vulnerability has been identified in
    MOVEit Transfer's web interface.  An attacker could craft a malicious payload targeting MOVEit Transfer
    users during the package composition procedure.  If a MOVEit user interacts with the crafted payload, the
    attacker would be able to execute malicious JavaScript within the context of the victims browser.
    (CVE-2023-42656)

  - In Progress MOVEit Transfer versions released before 2021.1.8 (13.1.8), 2022.0.8 (14.0.8), 2022.1.9
    (14.1.9), 2023.0.6 (15.0.6), a SQL injection vulnerability has been identified in the MOVEit Transfer
    machine interface that could allow an authenticated attacker to gain unauthorized access to the MOVEit
    Transfer database. An attacker could submit a crafted payload to the MOVEit Transfer machine interface
    which could result in modification and disclosure of MOVEit database content. (CVE-2023-42660)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Service-Pack-September-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42113f70");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2021.1.8, 2022.0.8, 2022.1.9, 2023.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_transfer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_dmz_ftp_installed.nbin");

  exit(0);
}

include('vcf.inc');

var appname = 'Ipswitch MOVEit DMZ';
var app_info = vcf::get_app_info(app:appname);

var constraints = [
  { 'max_version': '13.0.99999999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '13.1', 'fixed_version' : '13.1.8', 'fixed_display': '2021.1.8 (13.1.8)'},
  { 'min_version': '14.0', 'fixed_version' : '14.0.8', 'fixed_display': '2022.0.8 (14.0.8)'},
  { 'min_version': '14.1', 'fixed_version' : '14.1.9', 'fixed_display': '2022.1.9 (14.1.9)'},
  { 'min_version': '15.0', 'fixed_version' : '15.0.6', 'fixed_display': '2023.0.6 (15.0.6)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'sqli':TRUE, 'xss':TRUE}
);
