#TRUSTED 2a34e70482a5860fb9b34ac5cf87af259d7db2a0008df0ec76642fc8625ba708f05d3cbd005ac2575c038df76000a735981261e7e2f82b1c8bf157c6fd38fad9c692cd6c06e159e1036508bde51ca91a808c92f4fd8d8eb9a52bc44f3ed78ca0b13565eb82e540401825e3dc3519551fc8fae64f6419ef2c5bafcb3c74795a930a02a0dab1a5b6502699ff52c03ab51aa4813b863aa997bdaf9c38a339efe54bb42cfa95d763cf078fd4071775bafbcd0b7b7006b87a52fdb81a4b4eeca03d16359f59ca5f11755d11693a49c7ee1e0c2aedabad71fe48ac197c5ce91e676b8948bf516bda6df47fd2d50a49fe6435056caf4563e4eb2e3b1938b9c587510422f945b3154f9434c5423be60211714474ba7f8ee206bfa71551a4270109e30fb3e5f5b63992b6a83691e25a12542c1177791612bb6300e71466c105af69e4933c92f2f2cc84ba85a13e8f194bba42050a358c2340a87a0f4df1ccd8d60a09593323cd94e0998d168ac15dedbc73d44bb776cac40f072f3b8c68d93449f398aa36adbab4ed95a934a3d58f90ce77650481bbe689dc4f168e009a671773c8eab2cedd251852c34d1e52ff17fbf813f2821c21af133f78dd7e5fdc77ab0e0384b917dba86674f880083198a4006c2ce30f55c18068dcc747febacac4e66bbee7f15fd75dac3018b21efbbfde1bc1c2512c92174c8bccea2ae7f3c835abe3b10e8388
#TRUST-RSA-SHA256 641a3e8202ee4061bc35d5b2bfd10192f8ffd73f08bd5f481c64fdb4bb2ca336d0898df6d7466854b820c37643f996c2c31b755c6a8e0fe16b96ea6755a792aa578447974bc79db586f301a001121fd57c4afb011885b7890dbb7045a0d7a1e0c1b7ebf737dc85f644580a2703e3780379faeae7347a106c4267d9b78498c4d17b7f587e6d4b51208f2795b5b336a93216c7edd5e960f4521b3b054c948071958729a7178086cbe846d32834b3d772cbf1a9721bbde053b68d4e12cfe304d83a5532374734c4bdb6bcbc99029814530f4b2da60d93ee8e898d64bd39fe079c795425b60c0dfdf904c6ff22c208415d2f6a65c84f047e33fd7d33d0d62931f6181d9fd213d35ac633d8696f84afa75c515cf5ada7dad4dd2e82ec89d2f363061cc078fdcfa0cc22f26f6e3f149c8d4ccd23e8703b865ea3b68e672dae921c863d85c50c6c59072fda0e8444be729069a5f8f7e6918be69a36a2ebfd56525a4a9ecb250e9de1f8b93653ecc3e5da0146d3e10366431f3097157b0adb1c82fb4499d5ae49e3991b1b165777692fbff2ae3172390f6ea07f07db5edc3d9fa9fb0e8b308bf27ee1459efe152c8083228dc2b54a440efc76fb236e54025d8bb7dab3f478ea5be029d2db39ca877cc78ad8e7eedfcb10163b842ee7a592866548faeba1125d21fb944b4585ae9c0a1beeb0584c2510f9352cbe7fde8fe9bc5b0e851528
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139850);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12661");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw36015");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-vman-cmd-injection");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Virtualization Manager CLI Command Injection Vulnerability (cisco-sa-20190925-vman-cmd-injection)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by command injection vulnerability. A local,
authenticated attacker can exploit this to execute arbitrary code as root on the underlying system.  Please see the
included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-vman-cmd-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39d1eeaf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw36015");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuw36015");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12661");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '15.3.3S',
  '15.4.2S',
  '15.4.3S',
  '15.5.1S',
  '15.5.2S',
  '15.5.3S',
  '15.6.1S'
);

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCuw36015'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list);

