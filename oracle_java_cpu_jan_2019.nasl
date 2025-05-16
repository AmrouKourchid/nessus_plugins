#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121231);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2018-11212",
    "CVE-2019-2422",
    "CVE-2019-2426",
    "CVE-2019-2449"
  );
  script_bugtraq_id(
    106583,
    106590,
    106596,
    106597
  );

  script_name(english:"Oracle Java SE 1.7.x < 1.7.0_211 / 1.8.x < 1.8.0_201 / 1.11.x < 1.11.0_2 Multiple Vulnerabilities (January 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 7 Update 211, 8 Update 201,
11 Update 2. It is, therefore, affected by multiple vulnerabilities
related to the following components :

  - An issue in libjpeg 9a, a divide-by-zero error, could
    allow remote attackers to cause a denial of service
    condition via a crafted file. (CVE-2018-11212)

  - An unspecified vulnerability in Oracle Java SE in the
    Networking subcomponent could allow an unauthenticated,
    remote attacker with network access via multiple
    protocols to compromise Java SE.
    (CVE-2019-2426)

  - An unspecified vulnerability in Oracle Java SE in the
    Deployment subcomponent could allow an unauthenticated,
    remote attacker with network access via multiple
    protocols to compromise Java SE.
    (CVE-2019-2449)

  - An unspecified vulnerability in Oracle Java SE in the
    Libraries subcomponent could allow an unauthenticated,
    remote attacker with network access via multiple
    protocols to compromise Java SE.
    (CVE-2019-2422)

Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?799b2d05");
  # https://support.oracle.com/rs?type=doc&id=2485170.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1896887");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 11 Update 2, 8 Update 201 / 7 Update 211
or later. If necessary, remove any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2426");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_ports("SMB/Registry/Enumerated");
  script_require_keys("installed_sw/Java");
   
  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var os = get_kb_item('Host/OS');
if ('Windows' >!< os && empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  audit(AUDIT_OS_NOT, 'affected');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);
# 7u211, 8u201, 11u2
var constraints = [
  { 'min_version' : '7.0.0',  'fixed_version' : '7.0.211', 'fixed_display' : 'Upgrade to version 7.0.211 or greater' },
  { 'min_version' : '8.0.0',  'fixed_version' : '8.0.201', 'fixed_display' : 'Upgrade to version 8.0.201 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.2',  'fixed_display' : 'Upgrade to version 11.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
