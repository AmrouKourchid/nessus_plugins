#TRUSTED 81ab4c0b9a2f1c92563112f70dd6b40600c596400eec1dfe11f8ff56b93d014e46516a8e367f64c350a4a6bb27363a2c7438d28cf24d1815953905dfc94fd4867a48174de5380a073973c05a61231192d8c62d8e6a36b791fe4a8ba2d1c1bade43d05d2d0d7eb0d1bc2982a4ddc2bc62d3f8e1ca219574b3f2f85a64d075b59843006f7983c2fb43d6b44fb91931cbcd3a20f635afce0854cfda0f6b9da45aefea5c9d3ee767d06d8f9b7aab644dd99cd993e0872a1243e94b59f941f7447aa16e2ff93c818e2ee32a64d00a6e5f5a34e68a935e6baa2198538f62fc53a652c42c9e5772d324195d69ff7bbe4562e6d1cfadd1db5a063d899927947d6d342703b4155663bd4b352a35f3e70e10e81e8636d879217ac722f0329ba1b6adf39838009b6d3a9bc32be1952b45c5aa5e0686d25c2c7df8da81eb670442bfa39769e6c30f65a51445aa93402018f366beae308403f8d39333d34ca7993e1c4ac44fb0da63d6c2ea5795add8f309ce06924ae0cc39b466ac29a69463b44fb2ab9ba0a3a48ae422575b4d372cf8b70670d21b8ccd5cafc8eb480c8495bf0a31b96d10b814fff64db4c32a838b6af295258755bd157a2bc3a962139b81db4322be8afd75cec8740992c3c660d0f89c08a61a42e4c70675656c9e237ea940cd5c03c606e142b19314cfe81b817f979e7c0d04320cf0514dbd275aaa4b0239c975265ac82c
#TRUST-RSA-SHA256 639d5f8c787eefb4eacd422fe789ec0df5416aee49eb209694a1a25311a029954fcbd6786cb7bbcc11ddf7874fba08ea2d1a2fc7efd27c4a8caa38ac7eaf6c41f9f40e671af5399d0d12c76859abbcb87d6119ed72c16bb04c764f61095c74853aab3dc7e984fcf2f2731d8b49602520bc86ed2e313548638102d94ca58dcaf35b2476704ff2e1e327b9a8b87a070d4f87ea119183d0a9aa95450cfdaee122507910cc56eac29c50e99d3a99b0742023f2020211417f6933f938a82b492cd36ddaa2a255d17182b2328d29ed62f08d31e9fdb41cc5c65202b7c821a432cb948bfe972cbb8ad9b8687e12aaa89d7565154a9394ddedd0f167e2f3df4be44b50040406bda25eb22d8cad2dd8e3c580af165a5c052690cb7652337cde7dba2cb303abdf317a500e37146861e85d0a8f55eac8ef97427f57611a8030261b6e641b41d133a86c0667068ecf95b0cafea379009e86b163b5c7d0fe08fbb15f6016e29bfcee7f136e57770afe7993ab8709ac1ead04c52c989c047354676013a548a881a04e445694cc19bbcefc9d59b7cd8c4bc57e0b0b50c62967cf82d1bb582762409b4fbc25c1694f8edfdcb37f3213240b5d6d145e8a98b2645e3cadabd00118db6107835a81465913b448ab21655a54dbadd8a5fb58f8ab74f11ac417811b1ae228769f961a97e9de4765868b93d5b20f626e716c4c924ccb5830fa773c0abbe2
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153154);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/01");

  script_cve_id("CVE-2021-1385");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21776");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21783");
  script_xref(name:"IAVA", value:"2021-A-0141-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-pt-hWGcPf7g");

  script_name(english:"Cisco IOS Software IOx Application Environment Path Traversal (cisco-sa-iox-pt-hWGcPf7g)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a vulnerability.

  - A vulnerability in the Cisco IOx application hosting environment of multiple Cisco platforms could allow
    an authenticated, remote attacker to conduct directory traversal attacks and read and write files on the
    underlying operating system or host system. This vulnerability occurs because the device does not properly
    validate URIs in IOx API requests. An attacker could exploit this vulnerability by sending a crafted API
    request that contains directory traversal character sequences to an affected device. A successful exploit
    could allow the attacker to read or write arbitrary files on the underlying operating system.
    (CVE-2021-1385)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-pt-hWGcPf7g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?529bd81f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21776");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21783");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw64810, CSCvx21776, CSCvx21783");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1385");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var version_list=make_list(
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M4',
  '15.8(3)M5',
  '15.8(3)M6',
  '15.9(3)M',
  '15.9(3)M1',
  '15.9(3)M2',
  '15.9(3)M2a',
  '15.9(3)M3'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['ios_iox_host_list'],
  CISCO_WORKAROUNDS['iox_enabled']
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw64810, CSCvx21776, CSCvx21783',
  'cmds'     , make_list('show iox host list detail', 'show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
