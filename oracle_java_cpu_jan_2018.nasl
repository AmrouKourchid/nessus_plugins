#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106190);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2018-2579",
    "CVE-2018-2581",
    "CVE-2018-2582",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2602",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2627",
    "CVE-2018-2629",
    "CVE-2018-2633",
    "CVE-2018-2634",
    "CVE-2018-2637",
    "CVE-2018-2638",
    "CVE-2018-2639",
    "CVE-2018-2641",
    "CVE-2018-2657",
    "CVE-2018-2663",
    "CVE-2018-2677",
    "CVE-2018-2678"
  );
  script_bugtraq_id(
    102546,
    102556,
    102557,
    102576,
    102584,
    102592,
    102597,
    102605,
    102612,
    102615,
    102625,
    102629,
    102633,
    102636,
    102642,
    102656,
    102659,
    102661,
    102662,
    102663
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 9 Update 4, 8 Update 161,
7 Update 171, or 6 Update 181. It is, therefore, affected by
multiple vulnerabilities related to the following components :

  - AWT
  - Deployment
  - Hotspot
  - I18n
  - Installer
  - JCE
  - JGSS
  - JMX
  - JNDI
  - JavaFX
  - LDAP
  - Libraries
  - Serialization");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29ce2b01");
  # https://www.oracle.com/technetwork/java/javase/9-0-4-relnotes-4021191.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?793c3773");
  # https://www.oracle.com/technetwork/java/javase/8u162-relnotes-4021436.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc061f9a");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 9 Update 4, 8 Update 161 / 7 Update 171 /
6 Update 181 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 6u181, 7u171, 8u161, 9u4
var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.181', 'fixed_display' : 'Upgrade to version 6.0.181 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.171', 'fixed_display' : 'Upgrade to version 7.0.171 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.161', 'fixed_display' : 'Upgrade to version 8.0.161 or greater' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.4',   'fixed_display' : 'Upgrade to version 9.0.4 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
