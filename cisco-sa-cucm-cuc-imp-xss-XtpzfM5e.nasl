#TRUSTED 5e9307f8ad8c1af1c80b2b4409f6070144a612d88ecd420bd31dc14b8252b19eabbcffcbc8af15032b4ab8429d4ea0c6e1757240e0e214eaaa08548971f94fe4a9bdc8498a41becbc69f21af03db856e194aaf4772d3a3567d62a1e7c0b1c8cdc0b6f2ae6a324d7c51cdaa62feb9e1cd5644ca242de4559d21c459ebc41cf814c06b0dcb52c5b43f08f4a860c7b94ffb3b202084ffb84294daea2f0f370cb5fd5c042b6e0a5be430c11e4d55407c21ac010623e9b7aba9aed5419d09d2d855b8b65e4e5afdd42cce4108d8d886ddd8e414ead5b35c5216d745dc063567f332f3dccbbd1e0e5e9f779be29e9f67bfb4495825fae11fed02b50ea7d389adc8a503f8c9ad4ee84ce182a47627fd29d1be1b6870d7c3ad53f61cdbdca8c147374d29646d5cbc1bb55a26c1e98c80e97c602f39261cf490794c62575a40a315312719637e9b39e73b87a54fbab6d2810ae16c5da37a7dac893d9a208aaf4f914b1b2a743b326cda7fd8051e34aa6aa8465b6291249756920d3df97276a728c3b5f6bbca3f180dfac8e5b68820dc5a39d653205fecee64e514d9b3361682806daa50209f35279a99550193ec01556bef3c4c97d64ce411974196356de2242ff09a2a38e66a440f20e82289fe0d5eba457ceb4fd2275c93cb9dbf5ba6e9f284b2e2e2b30357c005b8de0edfa3926e758ca73121bfd6868a098198050be8872a3cf59a9f
#TRUST-RSA-SHA256 249251615c1f8a9656f3fbdd45f94fbcd7418463d55b802e4d4270747973c511ea653cd5b1a43464c41ecba80f040119a868097061987eb26c3af2f7cd774ffad18035e34afbec55d263e358249d92a16f7c1ce6a49fac4da202faea992f5eefa17097115ba744a955ff8aaf839adcbb77671d5481e649fecc136f6cd9592aa61cf72b33a5e68697cac5f47088a89106f753424bb8a314cd26279155e9aaf99808cde1673c5b49ad4fa23c8e358481200bf530c7a284bd52e901fdfc42b81e72f598bebf09be513eedfb36c92d0c134dd18a4da852fc904833c23942d1dd90b31355ff36ca81cbbe15948adc42f49154f83335839370d732b91f162dd56404613c7de2ebf4bdfbf2044fd9466149cb8c4f308af41758b862cda96bc630d1c128f806baa8e4c40c2d04da4881802f8efdf6d9e95bebed188c8231165dc43c1159038a2b45641a66a28dca007034a376213478c04238a03fed8ca7352981e00bc066811c91385ee84ecae4355baf0b361c98a8f5bd2642fa735e40ca6348b05b16a2f018bfddbe94b9f1a44ed7f28b7db532d4347e2e133de5347b203b99358c65b91363af35ed31b94944ad4b8f6220ca2d3adc73c7fc092834bf679bd339d34a0ec650a7ae0df5af7260253550dc0ed88d472b275f5c717e2be38f9939ce07977671d968820893688cb8205006a22fa5d42ac1a6260b4993985ce1f921daf0f7
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139792);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2020-3532");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt01179");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu30682");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu30689");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-cuc-imp-xss-XtpzfM5e");
  script_xref(name:"IAVA", value:"2020-A-0297-S");

  script_name(english:"Cisco Unified Communications Manager XSS (cisco-sa-cucm-cuc-imp-xss-XtpzfM5e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a cross-site scripting 
(XSS) vulnerability in its web interface component due to improper validation of user-supplied input before returning 
it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted 
URL, to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-cuc-imp-xss-XtpzfM5e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b594d314");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt01179");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu30682");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu30689");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory cisco-sa-cucm-cuc-imp-xss-XtpzfM5e");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3532");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# Neither advisory or BIDs state any fix version.
# BIDs simply say: No release planned to fix this bug
# Range is 0 to next release after highest vuln version in an attempt to flag for all current versions.
vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '12.5.1.13900.152'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvt01179, CSCvu30682, CSCvu30689',
  'disable_caveat', TRUE,
  'fix', 'No known fix, refer to Cisco advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

