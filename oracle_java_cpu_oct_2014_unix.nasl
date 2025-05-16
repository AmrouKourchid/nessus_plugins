#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78482);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id(
    "CVE-2014-4288",
    "CVE-2014-6456",
    "CVE-2014-6457",
    "CVE-2014-6458",
    "CVE-2014-6466",
    "CVE-2014-6468",
    "CVE-2014-6476",
    "CVE-2014-6485",
    "CVE-2014-6492",
    "CVE-2014-6493",
    "CVE-2014-6502",
    "CVE-2014-6503",
    "CVE-2014-6504",
    "CVE-2014-6506",
    "CVE-2014-6511",
    "CVE-2014-6512",
    "CVE-2014-6513",
    "CVE-2014-6515",
    "CVE-2014-6517",
    "CVE-2014-6519",
    "CVE-2014-6527",
    "CVE-2014-6531",
    "CVE-2014-6532",
    "CVE-2014-6558",
    "CVE-2014-6562"
  );
  script_bugtraq_id(
    70456,
    70460,
    70468,
    70470,
    70484,
    70488,
    70507,
    70518,
    70519,
    70522,
    70523,
    70531,
    70533,
    70538,
    70544,
    70548,
    70552,
    70556,
    70560,
    70564,
    70565,
    70567,
    70569,
    70570,
    70572
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2014 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 25, 7 Update 71, 6
Update 85, or 5 Update 75. It is, therefore, affected by security
issues in the following components :

  - 2D
  - AWT
  - Deployment
  - Hotspot
  - JAXP
  - JSSE
  - JavaFX
  - Libraries
  - Security");
  # https://www.oracle.com/technetwork/topics/security/alerts-086861.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b7fdf57");
  # https://www.oracle.com/technetwork/java/javase/8u25-relnotes-2296185.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?631ebd82");
  # https://www.oracle.com/technetwork/java/javase/7u71-relnotes-2296187.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd6e3a16");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84f3023c");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 8 Update 25, 7 Update 71, 6 Update 85, or 5 Update
75 or later and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 75 or later or 6 Update 85 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6456");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '5.0.0', 'fixed_version' : '5.0.75', 'fixed_display' : 'Upgrade to version 5.0.75 or greater' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.85', 'fixed_display' : 'Upgrade to version 6.0.85 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.71', 'fixed_display' : 'Upgrade to version 7.0.71 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.25', 'fixed_display' : 'Upgrade to version 8.0.25 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
