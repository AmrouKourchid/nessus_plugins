#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82821);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-0458",
    "CVE-2015-0459",
    "CVE-2015-0460",
    "CVE-2015-0469",
    "CVE-2015-0470",
    "CVE-2015-0477",
    "CVE-2015-0478",
    "CVE-2015-0480",
    "CVE-2015-0484",
    "CVE-2015-0486",
    "CVE-2015-0488",
    "CVE-2015-0491",
    "CVE-2015-0492"
  );
  script_bugtraq_id(
    71936,
    74072,
    74083,
    74094,
    74097,
    74104,
    74111,
    74119,
    74129,
    74135,
    74141,
    74145,
    74147,
    74149
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2015 CPU) (Unix) (FREAK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 45, 7 Update 79,
6 Update 95, or 5 Update 85. It is, therefore, affected by security
vulnerabilities in the following components :

  - 2D
  - Beans
  - Deployment
  - Hotspot
  - JavaFX
  - JCE
  - JSSE
  - Tools");
  # https://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56618dc1");
  # https://www.oracle.com/technetwork/java/javase/8u45-relnotes-2494160.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abb7def2");
  # https://www.oracle.com/technetwork/java/javase/7u79-relnotes-2494161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7736cf95");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84f3023c");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 45, 7 Update 79, 6 Update 95, or
5 Update 85 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 85 or later and 6 Update 95 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0460");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl", "sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '5.0.0', 'fixed_version' : '5.0.85', 'fixed_display' : 'Upgrade to version 5.0.85 or greater' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.95', 'fixed_display' : 'Upgrade to version 6.0.95 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.79', 'fixed_display' : 'Upgrade to version 7.0.79 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.45', 'fixed_display' : 'Upgrade to version 8.0.45 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
