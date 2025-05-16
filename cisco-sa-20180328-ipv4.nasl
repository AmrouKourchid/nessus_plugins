#TRUSTED 2cd0fd9d25675dd0e1e427da5da794eed7386565c38e9875a4b2fcf5a9a23a160168a105e84fb9aabb520ae1da9d5fc067d46559d217469d1881abebe9c493a8a4578594681333417cf3179e47856a84f44cd2d369b715cf6a6e96d1208097194ea7afc6930590cff7335eee1bb023d5106fe83c1fe3124e39f07497a41179949b28663704c22847e1fec8b03e8f1327be15f8c3458ad4fdd00004f76bc651513ae4f5080f738ea60b0d01e08a4c570ac72e344cc94b014e20a118a2ecc223d41419d5adfdc69cab49b92a4d718fe0218a13fb8e153f1ba5b019f653dcd9c22bceed3c2bb9743fe3714474fd34b38c9013e72712600d0ff2a4d6a20a834d749f4635785a37a70b8e97bd05f0facce66028161f0574271cfe9f5145fba4a86babcf6cfbce54d8de9fb5d2160bb4f34ae005b2bfb40ba6f145ace8e8f7417f8e058d6eaf98b0bf18d0bc498a540fca5901644ac41948eb2d8c89f533329d759724835f19b9b9bdc9b6be0318495f7ffa50cb277b34d3198ab1491012a2699bdb5a9e67af6f4725abbb99159322bc434bff1bf0682373f4360f749b90c4f38554ad59994de6c247d9aba8751687b87caba78f185890633b96104bc3ac43da9d2483d77e1098fe73844cdafd0661ab0dc0dc750ceceb5ca6753e9c8c00f1a44a0d80963c8908eaa1d3defa4afb20ec8a68320ec4b8c5c087179d43d3ed00aba3601a
#TRUST-RSA-SHA256 5cedb75d62ee8f8f1612be0d9d78716fed434748b45fb091c57554a8dc289a58f6079c747762da58c15f14577577273fc7c07f1a5a21a3c463cd6fb830358336b042527d0310f693d26f7577fb6a98ee879887724d7ed0ea5ca0f0c23cde6e7be28d4b9efec6eb78bb30eb04c3a06162cd86c05d7970dbe47caae701fd52c2ab4ae00a00db2cc1426bda4e5398747068e81634c6f97d038f9eb2a55669d02c259caecb2923504c76f9a67b84ac1540e48362a3274708efaede7244fafbd020fff042972a84b83b5f56219e18fe3ebf7de2938f422dc5bb03fbe2954761a23cf9b2b94efa878ad75d43dcf3671b6387948673a3ad0ec8ceb4ea302644f14c4cba73e4da58830d7a3d52efe3b7296db9902ba698110111f93e3bbe416e3f000a1bbf909f671b301323616b35d93ebef2d1dfe4c17dd8ef6ecb8d4d99905c44350d012367f384697c13a732bcffbcadd62409b323f968006d71f220ae0ff20c765ec85ceae20e60065416971c2c2bf095e88aede822aa3925da7dbde3aac798cfc62687ebf8250752bbe74e7bdf8bce555ca1941d042bfcad815daa4d068a19dad8835383e53477319980f0e24d04a80f64c0404962e1c60e25bcde2cf30eb6f8f50b4f43b93e4c2aae33217dfe08f43f0c76ccb373e63d2a52852924d717ad288f5332761ebfc84d4f547304ea65444c3fbcb30b3fc01d1a7b042da4f3a697eb36

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124196);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0177");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd80714");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-ipv4");

  script_name(english:"Cisco IOS XE Software for Cisco Catalyst Switches IPv4 Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by a vulnerability in the IP Version 4 (IPv4) processing code
of Cisco IOS XE Software running on Cisco Catalyst 3850 and
Cisco Catalyst 3650 Series Switches could allow an unauthenticated,
remote attacker to cause high CPU utilization, traceback messages,
or a reload of an affected device that leads to a denial of service
(DoS) condition.

The vulnerability is due to incorrect processing
of certain IPv4 packets. An attacker could exploit this vulnerability
by sending specific IPv4 packets to an IPv4 address on an affected
device. A successful exploit could allow the attacker to cause high
CPU utilization, traceback messages, or a reload of the affected
device that leads to a DoS condition. If the switch does not reboot
when under attack, it would require manual intervention to reload
the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-ipv4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a61dfafd");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd80714
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00b9b268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd80714");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");
device_model = get_kb_item_or_exit('Host/Cisco/device_model');
model = get_kb_item('Host/Cisco/IOS-XE/Model');

if( device_model !~ 'cat' || (model !~ '3850' && model !~ '3650')) audit(AUDIT_HOST_NOT, "affected");

version_list=make_list(
'3.18.3bSP',
'16.1.1',
'16.1.2',
'16.1.3',
'16.2.1',
'16.2.2',
'16.3.1',
'16.3.2',
'16.3.3',
'16.3.1a',
'16.4.1',
'16.4.2',
'16.4.3',
'16.5.1',
'16.5.1b'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd80714'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list);
