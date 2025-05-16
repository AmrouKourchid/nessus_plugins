#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88046);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id(
    "CVE-2015-7575",
    "CVE-2015-8126",
    "CVE-2016-0402",
    "CVE-2016-0448",
    "CVE-2016-0466",
    "CVE-2016-0475",
    "CVE-2016-0483",
    "CVE-2016-0494"
  );
  script_bugtraq_id(77568, 79684);

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2016 CPU) (SLOTH) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 71, 7 Update 95, or
6 Update 111. It is, therefore, affected by security vulnerabilities
in the following components :

  - 2D
  - AWT
  - JAXP
  - JMX
  - Libraries
  - Networking
  - Security");
  # https://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?376edd90");
  # https://www.oracle.com/technetwork/java/javase/8u71-relnotes-2773756.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7b6203b");
  # http://www.oracle.com/technetwork/java/javase/7u95-relnotes-2775806.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?796894ea");
  # https://www.oracle.com/technetwork/java/javase/6u111-relnotes-2775857.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b809e094");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/pages/attacks/SLOTH");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/downloads/transcript-collisions.pdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 71, 7 Update 95, 6 Update 111,
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 111 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0494");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2024 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.111', 'fixed_display' : 'Upgrade to version 6.0.111 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.95', 'fixed_display' : 'Upgrade to version 7.0.95 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.71', 'fixed_display' : 'Upgrade to version 8.0.71 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
