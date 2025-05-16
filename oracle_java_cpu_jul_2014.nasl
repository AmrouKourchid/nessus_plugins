#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76532);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id(
    "CVE-2014-2483",
    "CVE-2014-2490",
    "CVE-2014-4208",
    "CVE-2014-4209",
    "CVE-2014-4216",
    "CVE-2014-4218",
    "CVE-2014-4219",
    "CVE-2014-4220",
    "CVE-2014-4221",
    "CVE-2014-4223",
    "CVE-2014-4227",
    "CVE-2014-4244",
    "CVE-2014-4247",
    "CVE-2014-4252",
    "CVE-2014-4262",
    "CVE-2014-4263",
    "CVE-2014-4264",
    "CVE-2014-4265",
    "CVE-2014-4266",
    "CVE-2014-4268"
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 11, 7 Update 65, 6
Update 81, or 5 Update 71. It is, therefore, affected by security
issues in the following components :

  - Deployment
  - Hotspot
  - JavaFX
  - JMX
  - Libraries
  - Security
  - Serviceability
  - Swing");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4743a1ef");
  # http://www.oracle.com/technetwork/java/javase/8u11-relnotes-2232915.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81911044");
  # https://www.oracle.com/technetwork/java/javase/7u55-relnotes-2177812.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39cb260f");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84f3023c");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 8 Update 11, 7 Update 65, 6 Update 81, or 5 Update
71 or later and, if necessary, remove any affected versions.

Note that an extended support contract with Oracle is needed to obtain
JDK / JRE 5 Update 71 or later or 6 Update 81 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 5u71, 6u81, 7u65, 8u11
var constraints = [
  { 'min_version' : '5.0.0', 'fixed_version' : '5.0.71', 'fixed_display' : 'Upgrade to version 5.0.71 or greater' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.81', 'fixed_display' : 'Upgrade to version 6.0.81 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.65', 'fixed_display' : 'Upgrade to version 7.0.65 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.11', 'fixed_display' : 'Upgrade to version 8.0.11 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
