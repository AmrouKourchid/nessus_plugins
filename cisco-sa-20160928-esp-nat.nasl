#TRUSTED 150cf4fea40c82df51a6e7e1fac85898cd01b0728756cecb4d0429311786ec39b9e4cd8bf6e7c93fc6f27d035484d4739982ec67c32902870e1c5d13fd2599fc7fd35472d6d741ebe05f023653f468af1997e9be82040e4694e8de148ab9ee833f26d61e060b476ec4ac1247c0fbc1c92e8fc4366ddf5fa7744b8e8bbb4289661ede8c7ef5f67cd2b48f77471ea1b53b01e6746d6d0e77b5ba3d194ea2bad88328b37126aa78b76c72563186e88fb614e79807e29ec1904bfdfbbf5341db243953c07721902ce166a086ecd759d2e71e44c2f88941484a285e83ae25e17a1e6a3fe9c799bd96c77fd8f99cb78a01ee31fafdb14b289d5de784116bf618509185f439593aebe6143fe96ac1f079cd07729be4ba917918635124bc935834843c8a016fcfe697a1f00e7608dfffa23f9875c9184a02cca62ddea2a59638e158670c89823c55398f27dd1acc653ad80681fc03cc350b2333e5b9d473029a45956d8b5fa406faec3b5c4dec725ff3211913d49de9c018f94e50a30e06e95be221674bfba22b592d0cdc8d06c53de90e4a029f119bede7164d9799c51f9022ee1d7aa69270925b4125c52d719ddb1f6a83c70c222b47aeb19c51d6d2d5fe06bb0f1d833db794960e37fdbdcba735ae7b68fd9137c13d8fa9a5e80262589d2021d0e9b0558f0dbd3a957f7344d480609b0d503b90776593bbcdbebb1447eaa211b5c52d
#TRUST-RSA-SHA256 70d0be327b8940c0e4bab56453e17c534a7537614a2b142b515b5297648004e65666e5226a9282a3210773934921959686bab659f153546e77e0dfeed0e6ad459f30fc88579aa6dd54145cdd31349cf4c28e06e2993f8b2e6e6cb2a3bb6d1d6ec545b1fee529575f1cbc485c9bb35abc9de09377574f117d99eb20196c458a47d953e20622dd05731dd059368ba334c1a441f0d551d0b2877c6580cc12eac5309f58d3c4cadb7554a32f2ee77bab8d686919888610e339a69bfa09358f6764c25297347480315157ba027fd2d6d8fc1399790fb3ec5c483f8aba5ebb67baa3f88c5aad1afa45ee54287812608418e0e4c39af572ac279644210d19de036b68a91cd7469392593edd388f79939dbeda5eebc19227e1bf9ef73165516618c73324eb3d090a6045667a50e64d2bd36da311742d3e71dbb8c7e77f43f7a73ec3caa4479fc7103a9eb16a8b067c76f4ce2a4550cedf74bf80bc7f83f89aa0ac78e66ecf8edf50a6a91c4635b93819a3e5a610faef05e52a01e1fa579ed351cf3d6d4e70cd2d042fed0bf99344ccf3c63315d26359b24ed7d87cfbef447ff6df37faa6fde739d857ddbc76a323d425aaef8a556baf6ba6d6fee7c40ba21e4330631f0bfaefff31ffd58873f00690b0e9fa8d073f4dbc9c6d276c32c88d990f5e68cf164559d746130d6d468c2a8225329166cf6c1e76f96736be70406fcf5ac5d5a4e0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130763);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-6378");
  script_bugtraq_id(93200);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw85853");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-esp-nat");

  script_name(english:"Cisco IOS XE Software NAT DoS (cisco-sa-20160928-esp-nat)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the implementation of Network Address Translation (NAT) functionality due to improper handling of malformed ICMP
packets by the affected software. An unauthenticated, remote attacker could exploit this, via sending crafted ICMP
packets that require NAT processing by an affected device, to cause the device to reload repeatedly.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-esp-nat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c3c8ff3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw85853");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuw85853");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.2aS',
  '3.13.0aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.17.0S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.5.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['nat']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuw85853',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list);
