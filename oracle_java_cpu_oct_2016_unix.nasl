#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94139);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id(
    "CVE-2016-5542",
    "CVE-2016-5554",
    "CVE-2016-5556",
    "CVE-2016-5568",
    "CVE-2016-5573",
    "CVE-2016-5582",
    "CVE-2016-5597"
  );
  script_bugtraq_id(
    93618,
    93621,
    93623,
    93628,
    93636,
    93637,
    93643
  );
  script_xref(name:"EDB-ID", value:"118073");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2016 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 111, 7 Update 121,
or 6 Update 131. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the Libraries
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-5542)

  - An unspecified flaw exists in the JMX subcomponent that
    allows an unauthenticated, remote attacker to impact
    integrity. (CVE-2016-5554)

  - An unspecified flaw exists in the 2D subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-5556)

  - An unspecified flaw exists in the AWT subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-5568)

  - Multiple unspecified flaws exist in the Hotspot
    subcomponent that allow an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2016-5573,
    CVE-2016-5582)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5597)");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  # https://www.oracle.com/technetwork/java/javase/8u111-relnotes-3124969.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10d5f7a6");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 111 / 7 Update 121 / 6 Update
131 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5568");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");

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
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.131', 'fixed_display' : 'Upgrade to version 6.0.131 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.121', 'fixed_display' : 'Upgrade to version 7.0.121 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.111', 'fixed_display' : 'Upgrade to version 8.0.111 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
