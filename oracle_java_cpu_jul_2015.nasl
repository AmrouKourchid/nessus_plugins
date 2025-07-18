#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84824);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id(
    "CVE-2015-2590",
    "CVE-2015-2596",
    "CVE-2015-2601",
    "CVE-2015-2613",
    "CVE-2015-2619",
    "CVE-2015-2621",
    "CVE-2015-2625",
    "CVE-2015-2627",
    "CVE-2015-2628",
    "CVE-2015-2632",
    "CVE-2015-2637",
    "CVE-2015-2638",
    "CVE-2015-2659",
    "CVE-2015-2664",
    "CVE-2015-2808",
    "CVE-2015-4000",
    "CVE-2015-4729",
    "CVE-2015-4731",
    "CVE-2015-4732",
    "CVE-2015-4733",
    "CVE-2015-4736",
    "CVE-2015-4748",
    "CVE-2015-4749",
    "CVE-2015-4760"
  );
  script_bugtraq_id(
    73684,
    74733,
    75784,
    75796,
    75812,
    75818,
    75823,
    75832,
    75833,
    75850,
    75854,
    75857,
    75861,
    75867,
    75871,
    75874,
    75877,
    75881,
    75883,
    75887,
    75890,
    75892,
    75893,
    75895
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2015 CPU) (Bar Mitzvah)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 51, 7 Update 85, or
6 Update 101. It is, therefore, affected by security vulnerabilities
in the following components :

  - 2D
  - CORBA
  - Deployment
  - Hotspot
  - Install
  - JCE
  - JMX
  - JNDI
  - JSSE
  - Libraries
  - RMI
  - Security");
  # https://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3cf9c18");
  # https://www.oracle.com/technetwork/java/javase/8u51-relnotes-2587590.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?822f496a");
  # https://www.oracle.com/technetwork/java/javase/7u85-relnotes-2587591.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8497a5aa");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 51, 7 Update 85, 6 Update 101,
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4760");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable Network Security, Inc.");

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
# 6u101, 7u85, 8u51
var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.101', 'fixed_display' : 'Upgrade to version 6.0.101 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.85',  'fixed_display' : 'Upgrade to version 7.0.85 or greater'  },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.51',  'fixed_display' : 'Upgrade to version 8.0.51 or greater'  }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
