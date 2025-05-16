#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109203);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id(
    "CVE-2018-2783",
    "CVE-2018-2790",
    "CVE-2018-2794",
    "CVE-2018-2795",
    "CVE-2018-2796",
    "CVE-2018-2797",
    "CVE-2018-2798",
    "CVE-2018-2799",
    "CVE-2018-2800",
    "CVE-2018-2811",
    "CVE-2018-2814",
    "CVE-2018-2815",
    "CVE-2018-2825",
    "CVE-2018-2826"
  );
  script_bugtraq_id(
    103796,
    103810,
    103817,
    103832,
    103848,
    103849,
    103872
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2018 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 10 Update 1, 8 Update 171,
7 Update 181, or 6 Update 191. It is, therefore, affected by multiple
vulnerabilities related to the following components :

  - AWT
  - Concurrency
  - Hotspot
  - Install
  - JAXP
  - JMX
  - Libraries
  - RMI
  - Security
  - Serialization");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  # https://www.oracle.com/technetwork/java/javase/10-0-1-relnotes-4308875.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f630e2b");
  # https://www.oracle.com/technetwork/java/javase/8u171-relnotes-4308888.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bf6e180");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 10 Update 1, 8 Update 171 / 7 Update 181 /
6 Update 191 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2783");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.191', 'fixed_display' : 'Upgrade to version 6.0.191 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.181', 'fixed_display' : 'Upgrade to version 7.0.181 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.171', 'fixed_display' : 'Upgrade to version 8.0.171 or greater' },
  { 'min_version' : '10.0.0', 'fixed_version' : '10.0.1', 'fixed_display' : 'Upgrade to version 10.0.1 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
