#TRUSTED 8e32db2d210c1b183ab9ef675b386649bbda2736df8780fa4fb716e6af7b80d36e69d5570638ac2587c071782629b9341526617aacdc08afec647215768735cdbff79931829efa3074cc16f3dacb8f231a31a2d54bff4d1552f666440550e99a80734072124b8941f410f72acc039d626bb66d33c25b6b5cf36ead86a00934cf034f98c870c266b84c64c6c779f5f3e1cd1ef7c84ed040eff77ce1ee775f326cec3420a6225b9a637f3192c6c6cae970a7cbfa76e573264e286b55f8bbd176d44868540d28aedecfbdef88bff2d564b8f3d88175b938c024854c9db108493be3e9a896fd72e1fb72c788f51a46868134bc870f988f11b82e902e137b847cce2ec01550577d082a224ca0d8fbfe2351cf51415d5d977c6c94bbd0d87fb91d1521e279424625175226ea09afc1741a76e17048b2b80e5a609a16151b54888b82016038b7378036f6af09c670ce01d10b5a8cbbc5e70a8419b0c8c1445f16904a8ce971209e1c5bafae193fe40203b53fe0670099060e6a500618d3f1561c868286b7ef8638d8890be874f3565baa0299ba51b06176f22a1324813cef3a875398f5651e5e5a46747e463b91e95b0ddd19dc11e7d412dcc11db18af8f479de7bcd4cf7c4222ff6fa56a6221182f999b98af42fde7a6a16ad0b8443bf2a1d4a9743efcd6430161dd116e9c9e6651a62364a658aefb6108538c2375a870ae67f5cf934
#TRUST-RSA-SHA256 4ce8182a4ee7c154a4a08e293f34f5e58d5dc6a5a6df24c7ad21f9fc58ef60e9bf658478f4c4f071d941048fe2b413e575cc43ea3b2e21c4666e50f48fae50e0717ade945ec9cb1ff5afe6665aae2dd5e0a45959325cd0e18f1484af185812ce9921ceff5c4b550a6d1297dab08a733c278838f827e8803d59471947945be2443a31620b5067262813a36d94417ea51af126510af439d264ac3b378db5afba2561c082842320cf65287a951369409c19d44b34e4a05345f173e08f6cf5d4355c5889a89c66eadbac994c5a29d7d54371e783ff117edfafcd231b2b8b3503cff39af4e44b74e06dbf6af7972c94ffdf06f169e324d0d5b7a87109c6d604ccf0a007e7854d4476c56052d849e2d1dcd4339047a664ba85c9f266887c602ed76a2a2ff9da740eef4c777ad548d6121fa18ee88f7dd9bb00d7d89da351e02d7e02c31b30935ff79680a32dd16ccdb2029b64dd56128658c2c14c24967b38f22b929ce7e7d80fdeb0d15484caf3c43688d366820bfe6bf47895eb8c2ca45003bc7adfe81c70110ec4334f2d0a122ed7bf00b5451b12ede4a119d49dd72943b029f719d08c21ff346ce18621fc72c61cb9ea41a4b40f04ff2d6545aaff14b370de551b31dedf5e98650d0a1f2262af2d52267d928490a65d15ef88c996668d2fbec5a0ee844c390418b7a37241f4c727f870bcda55bc12736dac3a87b0de7293e8d24d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128526);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1737");
  script_bugtraq_id(107604);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf37838");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-ipsla-dos");

  script_name(english:"Cisco IOS and IOS XE Software IP Service Level Agreement Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability
in the processing of IP Service Level Agreement (SLA) packets by Cisco IOS Software and Cisco
IOS XE software, which could allow an unauthenticated, remote attacker to cause an interface
wedge and an eventual denial of service (DoS) condition on the affected device. The vulnerability
is due to improper socket resources handling in the IP SLA responder application code. An attacker
could exploit this vulnerability by sending crafted IP SLA packets to an affected device. An exploit
could allow the attacker to cause an interface to become wedged, resulting in an eventual denial of
service (DoS) condition on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ipsla-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74b82563");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf37838");
  script_set_attribute(attribute:"solution", value:"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf37838");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1737");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/05");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2S',
  '3.9.2E',
  '3.9.1aS',
  '3.9.1S',
  '3.9.1E',
  '3.9.0aS',
  '3.9.0S',
  '3.9.0E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2S',
  '3.8.2E',
  '3.8.1S',
  '3.8.1E',
  '3.8.0S',
  '3.8.0E',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.5E',
  '3.7.4aS',
  '3.7.4S',
  '3.7.4E',
  '3.7.3S',
  '3.7.3E',
  '3.7.2tS',
  '3.7.2S',
  '3.7.2E',
  '3.7.1aS',
  '3.7.1S',
  '3.7.1E',
  '3.7.0bS',
  '3.7.0S',
  '3.7.0E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.2E',
  '3.6.1E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.5.3E',
  '3.5.2E',
  '3.5.1E',
  '3.5.0E',
  '3.4.8SG',
  '3.4.7SG',
  '3.4.6SG',
  '3.4.5SG',
  '3.4.4SG',
  '3.4.3SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.0SG',
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SE',
  '3.2.3SE',
  '3.2.2SE',
  '3.2.1SE',
  '3.2.0SE',
  '3.2.0JA',
  '3.18.4S',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0cE',
  '3.10.0S',
  '3.10.0E',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.2',
  '16.4.1',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ip_sla'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf37838'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
