#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184810);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id("CVE-2023-23369");

  script_name(english:"QNAP QTS Command Injection (QSA-23-35)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS installed on the remote host is affected by a vulnerability as referenced in the QSA-23-35
advisory.

  - An OS command injection vulnerability has been reported to affect several QNAP operating system versions.
    If exploited, the vulnerability could allow users to execute commands via a network. We have already fixed
    the vulnerability in the following versions: Multimedia Console 2.1.2 ( 2023/05/04 ) and later Multimedia
    Console 1.4.8 ( 2023/05/05 ) and later QTS 5.1.0.2399 build 20230515 and later QTS 4.3.6.2441 build
    20230621 and later QTS 4.3.4.2451 build 20230621 and later QTS 4.3.3.2420 build 20230621 and later QTS
    4.2.6 build 20230621 and later Media Streaming add-on 500.1.1.2 ( 2023/06/12 ) and later Media Streaming
    add-on 500.0.0.11 ( 2023/06/16 ) and later (CVE-2023-23369)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-35");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-35 advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23369");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  { 'min_version' : '4.2.0', 'max_version' : '4.2.6', 'product' : 'QTS', 'fixed_display' : 'QTS 4.2.6 build 20230621', 'Build' : '20230621' },
  { 'min_version' : '4.3.3', 'max_version' : '4.3.3', 'product' : 'QTS', 'fixed_display' : 'QTS 4.3.3.2420 build 20230621', 'Number' : '2420', 'Build' : '20230621' },
  { 'min_version' : '4.3.4', 'max_version' : '4.3.4', 'product' : 'QTS', 'fixed_display' : 'QTS 4.3.4.2451 build 20230621', 'Number' : '2451', 'Build' : '20230621' },
  { 'min_version' : '4.3.6', 'max_version' : '4.3.6', 'product' : 'QTS', 'fixed_display' : 'QTS 4.3.6.2441 build 20230621', 'Number' : '2441', 'Build' : '20230621' },
  { 'min_version' : '5.1.0', 'max_version' : '5.1.0', 'product' : 'QTS', 'fixed_display' : 'QTS 5.1.0.2399 build 20230515', 'Number' : '2399', 'Build' : '20230515' }
];
vcf::qnap::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
