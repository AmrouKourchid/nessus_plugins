#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130011);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2019-2894",
    "CVE-2019-2933",
    "CVE-2019-2945",
    "CVE-2019-2949",
    "CVE-2019-2958",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2977",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2987",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2996",
    "CVE-2019-2999",
    "CVE-2019-11068"
  );
  script_xref(name:"IAVA", value:"2019-A-0385");

  script_name(english:"Oracle Java SE 1.7.0_241 / 1.8.0_231 / 1.11.0_5 / 1.13.0_1 Multiple Vulnerabilities (Oct 2019 CPU) (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 7 Update 241, 8 Update 231,
11 Update 5, or 13 Update 1. It is, therefore, affected by multiple
vulnerabilities related to the following components :

  - 2D
  - Libraries
  - Kerberos
  - Networking
  - JavaFX
  - Hotspot
  - Scripting
  - Javadoc
  - Deployment
  - Concurrency
  - JAXP
  - Serialization
  - Security

Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/security-alerts/cpuoct2019.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c94f8e4");
  # https://support.oracle.com/rs?type=doc&id=2589853.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?144b1a0e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 13 Update 1, 11 Update 5, 8 Update 231
/ 7 Update 241 or later. If necessary, remove any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
# 7u241, 8u231, 11u5, 13u1
var constraints = [
  { 'min_version' : '7.0.0',  'fixed_version' : '7.0.241', 'fixed_display' : 'Upgrade to version 7.0.241 or greater' },
  { 'min_version' : '8.0.0',  'fixed_version' : '8.0.231', 'fixed_display' : 'Upgrade to version 8.0.231 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.5',  'fixed_display' : 'Upgrade to version 11.0.5 or greater' },
  { 'min_version' : '13.0.0', 'fixed_version' : '13.0.1',  'fixed_display' : 'Upgrade to version 13.0.1 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
