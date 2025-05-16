#TRUSTED 67d41efa9d901a1c61091fe7bf98c1c25f0bee94e1e6b2b9035585aec4ca34c6fbf2b17aeb7efec882bf71e5e0b6140090cbc194a0841a3e49104248a296a2edbab7c663bdc9e1605bc074e1fc304839981266f069ec0e6aef7f2f0262f2a50c76d568b36edaadecff3fb56e1b42f0a0f5bf0d85b0d81108085f990bf049fa655898d9a325a5df608565417a05907d3a4f2d7425c338c5f3670c4b599ff83d30ecbc304d7829811a5099069d47e29be7f606ddc5ae715f918d32fb0d5383b2d2f999fc6bd436fef2c5a80f7773cd14764726815e0bdd58cd18fd41e360a4b38c355141b8e7a19c0ff72e899c9dae33e9117713ccdfae10c847fe29737f2678792fe64521aab9dee1dafde2b2625b2e4186c10e55f04081c20f8085d036a1f3db3fc145bab4ece1f0ad14fb867287eb8abb11616c1a1dea1d6291f20acee0fdbf635f56f5aaff1c4b2fce35777664ee1950a865a3c558022792c1248d05baedc7adb5b3102b95fb429fbfb54625839a15d3164b117b5a104ec635258fefca2f483702e9fcb97c8fbedb9ae756bb570e385776dc663e536489b257db32a6de16b4ed5858fb488f10c11349afd2dffcb8133a72e949b46f0aba3439bbfc0b1865a0d1180103eb51bd3ae90a08fb9539cfcb710d4930753c53bbd8707b3a53d57023e6c56091e353f0813c467af798951ee997b96045442b0b5ba4eec8833157eb12
#TRUST-RSA-SHA256 658296af1720d0de73c71d0abd3301f4a6496a7fcf8aef1e9a3e40d9efe1610c445019eef91d13a2e156332e024e023374480dcf261541a7866ebf851a0fe7537427ed8e0c034fcf28db774ef3b0f445e5fca2e07a31f48731898574e45e8d9914cd8b3693b3b806ba09019fa5f389ce7ea6279c1a30266cac825dec6ea92dee02d012f350feabb9e155e4fc408d60a74c4501044c14730eea8b5d0eb91c8c9d51d228512fb6a623bdf5aa2d527d2ae7b5e2362ceb335e23006b28785d77cadb9394cebc4e4449862a2390abcad77d8a2b7c8c397180b60eb3c0cbb7aba71d3edd6f0e76ea39718763db7b89d7623f3cb52f367013e3d28151c4afe89195009db2b4fed12f69a89c0eaec7f2d101ef6be8868c564c556c2fd911fc93def32202ccc70422aeb5a8e8f9fe215444df287abd5c1f9d978321b1abd1a905fd985971c756e76c62bf0664f8de288b9284e72f988b998275f04fef75a0e5c7e454c49c7820c8d981ca4e6140855fff9eddc538d401a6d0a5900a4f2b66bdeeec0995bb78eb2c2b8d3e44339615b1edff1ff3b4b24c3f591a74903a48ef5979c4fe801cebc19e5a108948a83d42cfb4bef192065eaf1acb29e8b39160ffb798efb58d88529b284ae3b1364b83ed9866aab62d4cd020663e2ad7060060efba0246f2ef0a7ff2820add0249f7b0a3b7ec676b3258a3397710e984a80795ececeea1e500dd
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117956);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2018-0469");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva31961");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-webuidos");

  script_name(english:"Cisco IOS XE Software Web UI DoS Vulnerability (cisco-sa-20180926-webuidos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-webuidos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cba237c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva31961");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCva31961.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0469");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.2.1",
  "16.2.2",
  "16.3.1",
  "16.3.2",
  "16.3.3",
  "16.3.1a",
  "16.3.4",
  "16.3.5",
  "16.3.5b",
  "16.3.6",
  "16.3.7",
  "16.4.1",
  "16.4.2",
  "16.4.3",
  "16.9.1b",
  "16.9.1h"
  );

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCva31961",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
