#TRUSTED 2ba9121189a962b7cd4abcc4f38bfac2b6fec58cd3f86be10b33e1a81ae08ec769c0d470235558ef1b14552674715ba9da61ddf15bb0a6d300b6c25d82420c5b9b80e9a2432416bda0e33ebc6237ff834bafe9c8d42d3bc0d69896893b3bd09c03f8c5db99b3a2dce8c623b7626e6be6a280775a64dd27ed3dca2fbda2e106766c42cc0427553631a47b4a846f82833508abfe82acf982a6334f3e28215c48e8dbbffb1bb6cd9c34eeea878afb81dd92ed2c28201dbb806add09acb575200bc8e80a5920c98718196fc52de08a01222de19af0f68bd5c2ba746d615270e643eaac8e63c8481ea6d3e9f0aa1dd21a6b8c91937b7eef98b9e173162cb1f09b3dd60fe4a61abdf6427d0ffae4ae7b26cdec81e7278f469cf2adddcd91a12b53e49eebc4e81c409e284927d89f7c25b272fa47108394f2992dec781fdbe68dfe25075f4449bd8764e323ec254faf0ca020386be43e65cefcbe8b2a357ce0421ce7ccb1b26d9bb806546e64c1526b3ddfbb69ef8cd740ddf955568ec89c416505ff369ae8824804560f448fb59c481cd094cb8b23fe87d058d22a8c3feec7fd849172444df44eaa7c512591cf7d1f1be9c041a27e95dceed40c091c55360bbfd9b48210bf502ab90e46a612277dbb16e0025cd7c7e406725d9c2a4ef6b7f62a1107178b96125a1321f724d1258f83eba1e97608faabfa514ada0a97f780be1a8f7950
#TRUST-RSA-SHA256 a946feed95143b5053523facb32d379fdb78d6f5b49a3727ab71c57a80561fe2ea2191e3688a1c061d2437b59b7ad74b7b33c814cb7a974fae311f86ec3989d4dcd38f669672da1233ae92b62ab9832a32235437caba8fb18dbd498b05fa91f167258f2951a26f49a10799ada20af7e6b88928f74dfd76e82f3a1cd10123cffc834973fa70be56e342e400c71953fdb1bc2c9447bf66bfda46eb11aa78f81962d616b23a733e6dafd4df8b1f20f65c2c9ccb96d00f91cefc55aba0cf338b2cb54b26b7525d34a426fa97b48626d9c4137b21ff66c0849432ad3dac3cc924c813e65bcfa25169aaec311768561f9177c2ad78f5d3886dd660ddfadf5c87c0d95a177508c9fd1d5dba5a550723f56d23cbf485256526b20bcf857b5a5feead45bf4e376d2354b67c0eb2eb05c5359f7551e21118c16ac362cd244ca2aa905ec114657762f3b4893ac39a50637dd9c54f8c7b4d2c3150dff3ebc353583dea122f2584a7b8cb01d1c9d5a266dd419f2209984b0e9284cbd136739e86f8e9a9ff5b02aee676540b70be208c5716b5a56d9ee5cfc3cf665be89a13ff9b5426560f40ad8d83e02f778fb6815bbde9d52feccd3852f4a1f7248895e993a35a5902bc08068d05676da5b225947a2504ec6de6d3709e45723da9f755adc6078edb498c9326b191333568e42b5ed65655c823b7b48f8e0ab2b1ce61c51c4bf9f6a33ed531a5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139232);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3375");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11538");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdbufof-h5f5VSeL");
  script_xref(name:"IAVA", value:"2020-A-0348-S");

  script_name(english:"Cisco SD-WAN Solution Software Buffer Overflow Vulnerability (cisco-sa-sdbufof-h5f5VSeL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by a buffer overflow vulnerability. 
This could allow an unauthenticated, remote attacker to cause a buffer overflow on an affected device.
The vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability 
by sending crafted traffic to an affected device. A successful exploit could allow the attacker to 
gain access to information that they are not authorized to access, make changes to the system that 
they are not authorized to make, and execute commands on an affected system with privileges of the 
root user.
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdbufof-h5f5VSeL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5771685");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11538");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt11538");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3375");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe_sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

version_list=make_list(
  '16.9.4',
  '16.9.3',
  '16.9.2',
  '16.9.1',
  '16.9.0',
  '16.12.2r',
  '16.12.1e',
  '16.12.1d',
  '16.12.1b',
  '16.12.0',
  '16.11.1a',
  '16.11.0',
  '16.10.4',
  '16.10.3b',
  '16.10.3a',
  '16.10.3',
  '16.10.2',
  '16.10.1',
  '16.10.0',
  ''
);

var sdwan = get_kb_item('Host/Cisco/SDWAN/Version');
var model_check = product_info['model'];

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

if(sdwan !~ "([0-9]\.)+")
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt11538',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
