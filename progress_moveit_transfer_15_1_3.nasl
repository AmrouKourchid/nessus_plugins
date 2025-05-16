#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189183);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/19");

  script_cve_id("CVE-2024-0396");
  script_xref(name:"IAVA", value:"2024-A-0046");

  script_name(english:"Progress MOVEit Transfer < 2022.0.10 / 2022.1 < 2022.1.11 / 2023.0 < 2023.0.8 / 2023.1 < 2023.1.3 Multiple Vulnerabilities (January 2024)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Progress MOVEit Transfer, formerly Ipswitch MOVEit DMZ, installed on the remote host is therefore, 
affected by multiple vulnerabilities as referenced in Progress Community article 000249475.

 - In Progress MOVEit Transfer versions released before 2022.0.10 (14.0.10), 2022.1.11 (14.1.11), 2023.0.8 
   (15.0.8), 2023.1.3 (15.1.3), an input validation issue was discovered.  An authenticated user can 
   manipulate a parameter in an HTTPS transaction.  The modified transaction could lead to computational 
   errors within MOVEit Transfer and potentially result in a denial of service. (CVE-2024-0396)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Service-Pack-January-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61c987f7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2022.0.10, 2022.1.11, 2023.0.8, 2023.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_transfer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'max_version': '13.1.99999999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '14.0', 'fixed_version' : '14.0.10', 'fixed_display': '2022.0.10 (14.0.10)'},
  { 'min_version': '14.1', 'fixed_version' : '14.1.11', 'fixed_display': '2022.1.11 (14.1.11)'},
  { 'min_version': '15.0', 'fixed_version' : '15.0.8', 'fixed_display': '2023.0.8 (15.0.8)'},
  { 'min_version': '15.1', 'fixed_version' : '15.1.3', 'fixed_display': '2023.1.3 (15.1.3)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
