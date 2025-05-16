#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73570);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2013-6954",
    "CVE-2014-0429",
    "CVE-2014-0432",
    "CVE-2014-0446",
    "CVE-2014-0448",
    "CVE-2014-0449",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0454",
    "CVE-2014-0455",
    "CVE-2014-0456",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0459",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-0463",
    "CVE-2014-0464",
    "CVE-2014-1876",
    "CVE-2014-2397",
    "CVE-2014-2398",
    "CVE-2014-2401",
    "CVE-2014-2402",
    "CVE-2014-2403",
    "CVE-2014-2409",
    "CVE-2014-2410",
    "CVE-2014-2412",
    "CVE-2014-2413",
    "CVE-2014-2414",
    "CVE-2014-2420",
    "CVE-2014-2421",
    "CVE-2014-2422",
    "CVE-2014-2423",
    "CVE-2014-2427",
    "CVE-2014-2428"
  );
  script_bugtraq_id(
    63676,
    64493,
    65568,
    66856,
    66866,
    66870,
    66873,
    66877,
    66879,
    66881,
    66883,
    66886,
    66887,
    66891,
    66893,
    66894,
    66897,
    66898,
    66899,
    66902,
    66903,
    66904,
    66905,
    66907,
    66908,
    66909,
    66910,
    66911,
    66912,
    66913,
    66914,
    66915,
    66916,
    66917,
    66918,
    66919,
    66920
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 8 Update 5, 7 Update 55,
6 Update 75, or 5 Update 65.  It is, therefore, potentially affected
by security issues in the following components :

  - 2D
  - AWT
  - Deployment
  - Hotspot
  - JAX-WS
  - JAXB
  - JAXP
  - JNDI
  - JavaFX
  - Javadoc
  - Libraries
  - Scripting
  - Security
  - Sound");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e3ee66a");
  # https://www.oracle.com/technetwork/java/javase/8train-relnotes-latest-2153846.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f65f6f6e");
  # https://www.oracle.com/technetwork/java/javase/7u55-relnotes-2177812.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39cb260f");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84f3023c");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 8 Update 5, 7 Update 55, 6 Update 75, or
5 Update 65 or later and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 65 or later or 6 Update 75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0429");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

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
# 5u65, 6u75, 7u55, 8u5
var constraints = [
  { 'min_version' : '5.0.0', 'fixed_version' : '5.0.65', 'fixed_display' : 'Upgrade to version 5.0.65 or greater' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.75', 'fixed_display' : 'Upgrade to version 6.0.75 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.55', 'fixed_display' : 'Upgrade to version 7.0.55 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5',  'fixed_display' : 'Upgrade to version 8.0.5 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
