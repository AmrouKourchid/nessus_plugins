#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80907);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2014-6549",
    "CVE-2014-6585",
    "CVE-2014-6587",
    "CVE-2014-6591",
    "CVE-2014-6593",
    "CVE-2014-6601",
    "CVE-2015-0383",
    "CVE-2015-0395",
    "CVE-2015-0400",
    "CVE-2015-0403",
    "CVE-2015-0406",
    "CVE-2015-0407",
    "CVE-2015-0408",
    "CVE-2015-0410",
    "CVE-2015-0412",
    "CVE-2015-0413",
    "CVE-2015-0421",
    "CVE-2015-0437"
  );
  script_bugtraq_id(
    70574,
    72132,
    72136,
    72137,
    72140,
    72142,
    72146,
    72148,
    72150,
    72154,
    72155,
    72159,
    72162,
    72165,
    72168,
    72169,
    72173,
    72175,
    72176
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2015 CPU) (Unix) (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Java SE or Java for Business installed on the
remote host is prior to 8 Update 31, 7 Update 75, 6 Update 91, or 5
Update 81. It is, therefore, affected by security vulnerabilities in
the following components :

  - 2D
  - Deployment
  - Hotspot
  - Install
  - JAX-WS
  - JSSE
  - Libraries
  - RMI
  - Security
  - Serviceability
  - Swing");
  # https://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75c6cafb");
  # https://www.oracle.com/technetwork/java/javase/8u31-relnotes-2389094.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17bff27a");
  # https://www.oracle.com/technetwork/java/javase/7u75-relnotes-2389086.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64c6b956");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84f3023c");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 8 Update 31, 7 Update 75, 6 Update 91, or 5 Update
81 or later, and if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 81 or later, or 6 Update 91 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0408");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '5.0.0', 'fixed_version' : '5.0.81', 'fixed_display' : 'Upgrade to version 5.0.81 or greater' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.91', 'fixed_display' : 'Upgrade to version 6.0.91 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.75', 'fixed_display' : 'Upgrade to version 7.0.75 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.31', 'fixed_display' : 'Upgrade to version 8.0.31 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
