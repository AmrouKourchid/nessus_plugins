#TRUSTED 81a476bfd03b20a0b16dc1b1d699c8d5ea374c010b5c2b06e103bcb8bc814b238e1ba4e83fe75aa17839258d6ad6e0413b68dc7164f577c0201895263f0300c05317014aefbd67dc059692deec80328f5c6f30578dbea3170252c212c68bf71ed0162692ed9a2bbbf2f1054b30b8bbf12f8af601ab75fcb55db664f572467040c71b63d669883f40e0b480f8f17d064c944213732e40bc6732147af59ca93bb9fbf6ebf27caa19628c355a54b82caaca9b2d7bc4b60bfb732967b6d1ffa2b636c20dd13e700e381cdf53e886b8712c752d5bdba4c0b4e26e43f851b8ee3b24c63e53755e16761cfced3c680bd1cf1471b81f08c9c57b6b932de89fb21ff9937201fd4e27029460cc55960233ee68dc619b966c3a3f83cbbd9f68ae79addf0d42843f63a5d9b577b2175290ba12b81c1e32122649c23d6d7c07c0477e71db6ec27394ba2c4d87ce694db00d386858a43c51f1c28cf8bc53bf80126ac96e55dd5a7ae40763ecc87f542f3b68f355bd12cca0934cb0492a31be3ee706ee166fd8d0839a6b5cf48432dd17493f200b44546d3e1cf60d486c1a824721ee3bd7b139ef5fc1f872ae6059acd367e24956b909bef1d3edceeb19dd9d4576173e134f68a38e9e44095197ca5d55dd2b85852aabfe2435ca958d6ac1fe157f69b64804658a43da3c6d7e70c6eeb8de2e0a2db97f6d9a137158e555eb4a3573e9ee76f49547
#TRUST-RSA-SHA256 8d018124b600785816e8fe75df7211a4fd5086b9c0c3c38cf8b42142700508a01c024035cd594afac48761e9a7cc30400092aee22bc5210c8ebbe75cb5355944d0e311a16563f15a002b418a3e72e3856222d2bf9bfbda2a832d27020a5d258d900a4c971357f642f988a133ea4a7d6a50998f3be3c0fd59588edae0147082d61b863375ad3f7c51e1c45f2042afb433361ef73802de5945a997f28fafdacb55120a1b5caf27082a17a315d3b7d455fc5f6e81f316ea5bf07cb395d61d75f2588b2e01e88bff0af5014bb2da8a64fadc6c28dc05de110c46c9e61a558143711e8fd548fbf283307f749a84983cc820e188b8aca910c9aab4d2553f33e2abd41edf306a49f071455a0119aa7d71cb9cef115350b5bd45082a5f699f778cc00fa7488b25abbef4e4271372422e9e4cfce860ae233a93547defe601c4cff0ddba469cf9e5aa5ea813d4e3163dfda3ad19a7935822410d3d176a5b9a5f70fe5e18ae68dc4437851edeb347ce97144efeb6b1b7df643066b8fd42307042079a86a200e332168151b67a29f17cc3859e34ba1e9f5f6b556a7eba4b79b4ce03094666a6c33c618cc39b72b8f4157fe9e6eb522afcc90df4ae92fc2d7cdbc0a98f7b588d4f53da0cab3080d8c8babbb5f5e730172a75cd6de79dcf4de5edba5dbf49c6b6aaf5aaf6461dabe7cc8da1b7960e4bf5a474ca873942fc223208850502b412d7
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193583);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20373");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe24431");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snmp-uwBXfqww");
  script_xref(name:"IAVA", value:"2024-A-0251-S");

  script_name(english:"Cisco IOS Software SNMP Extended Named Access Control List Bypass (cisco-sa-snmp-uwBXfqww)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-uwBXfqww
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2d0fc83");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe24431");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe24431");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco IOS');

var version_list=make_list(
  '12.2(6)I1',
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVR3',
  '15.1(3)SVR10',
  '15.1(3)SVS',
  '15.1(3)SVS1',
  '15.1(3)SVT1',
  '15.1(3)SVT2',
  '15.1(3)SVT3',
  '15.1(3)SVT4',
  '15.1(3)SVU1',
  '15.1(3)SVU2',
  '15.1(3)SVU10',
  '15.1(3)SVU11',
  '15.1(3)SVU20',
  '15.1(3)SVU21',
  '15.1(3)SVV1',
  '15.1(3)SVV2',
  '15.1(3)SVV3',
  '15.1(3)SVV4',
  '15.1(3)SVW',
  '15.1(3)SVW1',
  '15.1(3)SVX',
  '15.1(3)SVX1',
  '15.2(1)SY3',
  '15.2(1)SY4',
  '15.2(1)SY5',
  '15.2(1)SY6',
  '15.2(1)SY7',
  '15.2(1)SY8',
  '15.2(2)SY1',
  '15.2(2)SY2',
  '15.2(2)SY3',
  '15.2(4)E2',
  '15.2(4)E3',
  '15.2(4)E4',
  '15.2(4)E5',
  '15.2(4)E5a',
  '15.2(4)E6',
  '15.2(4)E7',
  '15.2(4)E8',
  '15.2(4)E9',
  '15.2(4)E10',
  '15.2(4)E10a',
  '15.2(4)E10b',
  '15.2(4)E10c',
  '15.2(4)E10d',
  '15.2(4)E10e',
  '15.2(4m)E2',
  '15.2(4m)E3',
  '15.2(4n)E2',
  '15.2(4o)E2',
  '15.2(4o)E3',
  '15.2(4p)E1',
  '15.2(4q)E1',
  '15.2(4s)E1',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EA',
  '15.2(5)EX',
  '15.2(5a)E',
  '15.2(5a)E1',
  '15.2(5b)E',
  '15.2(5c)E',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E2b',
  '15.2(6)E3',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0a',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7)E2a',
  '15.2(7)E2b',
  '15.2(7)E3',
  '15.2(7)E3k',
  '15.2(7)E4',
  '15.2(7)E5',
  '15.2(7)E6',
  '15.2(7)E7',
  '15.2(7)E8',
  '15.2(7)E9',
  '15.2(7)E10',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.2(8)E',
  '15.2(8)E1',
  '15.2(8)E2',
  '15.2(8)E3',
  '15.2(8)E4',
  '15.2(8)E5',
  '15.3(0)SY',
  '15.3(1)SY',
  '15.3(1)SY1',
  '15.3(1)SY2',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.4(1)SY4',
  '15.4(3)M6',
  '15.4(3)M6a',
  '15.4(3)M7',
  '15.4(3)M7a',
  '15.4(3)M8',
  '15.4(3)M9',
  '15.4(3)M10',
  '15.5(1)SY',
  '15.5(1)SY1',
  '15.5(1)SY2',
  '15.5(1)SY3',
  '15.5(1)SY4',
  '15.5(1)SY5',
  '15.5(1)SY6',
  '15.5(1)SY7',
  '15.5(1)SY8',
  '15.5(1)SY9',
  '15.5(1)SY10',
  '15.5(1)SY11',
  '15.5(1)SY12',
  '15.5(1)SY13',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M5',
  '15.5(3)M6',
  '15.5(3)M6a',
  '15.5(3)M7',
  '15.5(3)M8',
  '15.5(3)M9',
  '15.5(3)M10',
  '15.5(3)M11',
  '15.5(3)M11a',
  '15.5(3)M11b',
  '15.6(2)T',
  '15.6(2)T0a',
  '15.6(2)T1',
  '15.6(2)T2',
  '15.6(2)T3',
  '15.6(3)M',
  '15.6(3)M0a',
  '15.6(3)M1',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.6(3)M7',
  '15.6(3)M8',
  '15.6(3)M9',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1',
  '15.7(3)M2',
  '15.7(3)M3',
  '15.7(3)M4',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5',
  '15.7(3)M6',
  '15.7(3)M7',
  '15.7(3)M8',
  '15.7(3)M9',
  '15.7(3)M10',
  '15.7(3)M10a',
  '15.7(3)M10b',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M0b',
  '15.8(3)M1',
  '15.8(3)M1a',
  '15.8(3)M2',
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.8(3)M4',
  '15.8(3)M5',
  '15.8(3)M6',
  '15.8(3)M7',
  '15.8(3)M8',
  '15.8(3)M9',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.9(3)M1',
  '15.9(3)M2',
  '15.9(3)M2a',
  '15.9(3)M3',
  '15.9(3)M3a',
  '15.9(3)M3b',
  '15.9(3)M4',
  '15.9(3)M4a',
  '15.9(3)M5',
  '15.9(3)M6',
  '15.9(3)M6a',
  '15.9(3)M6b',
  '15.9(3)M7',
  '15.9(3)M7a',
  '15.9(3)M8',
  '15.9(3)M8a',
  '15.9(3)M8b',
  '15.9(3)M9',
  '15.9(3)M9a'
);

# Due to the nature and the back and forth of confirming the workaround
# This plugin has been determined to be best served with the Paranoid setting.

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe24431'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
