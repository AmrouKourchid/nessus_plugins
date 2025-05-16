#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86542);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id(
    "CVE-2015-4734",
    "CVE-2015-4803",
    "CVE-2015-4805",
    "CVE-2015-4806",
    "CVE-2015-4810",
    "CVE-2015-4835",
    "CVE-2015-4840",
    "CVE-2015-4842",
    "CVE-2015-4843",
    "CVE-2015-4844",
    "CVE-2015-4860",
    "CVE-2015-4868",
    "CVE-2015-4871",
    "CVE-2015-4872",
    "CVE-2015-4881",
    "CVE-2015-4882",
    "CVE-2015-4883",
    "CVE-2015-4893",
    "CVE-2015-4901",
    "CVE-2015-4902",
    "CVE-2015-4903",
    "CVE-2015-4906",
    "CVE-2015-4908",
    "CVE-2015-4911",
    "CVE-2015-4916"
  );
  script_bugtraq_id(
    77126,
    77148,
    77159,
    77160,
    77162,
    77163,
    77164,
    77181,
    77192,
    77194,
    77200,
    77207,
    77209,
    77211,
    77214,
    77221,
    77223,
    77225,
    77226,
    77229,
    77238,
    77241,
    77242
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 65, 7 Update 91, or
6 Update 105. It is, therefore, affected by security vulnerabilities
in the following components :

  - 2D
  - CORBA
  - Deployment
  - JavaFX
  - JAXP
  - JGSS
  - Libraries
  - RMI
  - Security
  - Serialization");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e5158e8");
  # https://www.oracle.com/technetwork/java/javase/8u65-relnotes-2687063.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31d5ce9a");
  # https://www.oracle.com/technetwork/java/javase/7u91-relnotes-2687180.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4da55863");
  # https://www.oracle.com/technetwork/java/javase/6u105-relnotes-2703317.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af476d66");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 65, 7 Update 91, 6 Update 105,
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4883");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");

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
# 6u105, 7u91, 8u65
var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.105', 'fixed_display' : 'Upgrade to version 6.0.105 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.91',  'fixed_display' : 'Upgrade to version 7.0.91 or greater'  },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.65',  'fixed_display' : 'Upgrade to version 8.0.65 or greater'  }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
