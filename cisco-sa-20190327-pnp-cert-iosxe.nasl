#TRUSTED a190ef5ff49889293895e21368fd739f01ed92412cc31d91b949d1442b2b0cf025b2506a40abafdbc5b309e63b21cba8ccf1a20ae206550d63d43734541951a241916a11b5c51d6da823b76ad519916d3b6776ea70c995f755883f2149fa0999b5d694c138ee7484f9273b2cb67a9d116909d697e7fb13da11989b3b11e2546117c4c41218748dedb2161a6bf690fc3a99270e170e791f873c9ee3d95f901a0d75714ffc172edb440f59a896416192648ef5d3515da99376ee67fa2a34a5a8a08fc0391ae545811eb591e3e5d35d4c17c9ccada810c175c37540b2a460af7fffda787e09959faef900d6671348021cacc29bae4b0e6983799aaa9acaf5f4365cd990440968aea3c9bf9b3de53b4680e2a4dccbeb60cad370470478f872c40df15d3740777537c2b014af56be536418db2c7df2559208b281f43e1aadf4f795c756b5b0ebf2204e8bf65f554631ce7c5edd148dd2f0dd36d83dc8856ebeb8154b8c57d8237bef44f1940248f6a3aadb4f3928d9c35835178e8eff52dda81b0ee11ae74673be1c00680acedefa9604705ee8a94c3b4fb8172e3d1752108dc845ef428d78f638c0d82a8ee54f996d30bff3d1e37e5861f0aa033e3c37c0e4af4fcb9c14367ce7859338a9fd4aa491c380962e34700b596b71016ffcdbe79eb00ef7ba51a980e90e7f173fdcd2c740d722cc67eb710d8f9816f501d2b46d1b345c53
#TRUST-RSA-SHA256 139ccfc08a2889b2939f4fe3ae92320fdd7d99bec8085694966706ad5bc38e3d98b0b23c64dbae1057661a7176758c9d35a25e10529dbcedd722a3e9e8fa1a515c7221eedf4c3422f20fa1fb950ab254f945403b4553bc0d708b56d42e9ec1857b214fb20ad1bc7e6738ebc5a1ecade0a91264ce2c016856fa8b4e7dff0ac97fee64dbbb8748e429259a34edba6cc8816eaa4c7861a807cd31895d305f277727750beb0e97cde1016d5ecdc2e7c070fb5e7b07cf456e0af6c9512ee88a845f3f9675f3a21ba5a9ba3c7f51215d96dc4f9fc5d93fc4ea811bd21feed273ffff2f358e16307ba94fad68387f0be392dc5183738a5912c450fdce371917f84c1278035ff2da4bcda4ad73e141acf0b897b544d30f91afcdcd52197035e25ea856b2c59a79a1c940565fcb74bf0b9cb5d6260b22c8627543915786cd9166a519f54b6603790b6242f3cc2279b93a07b93ec847abc5c9de5f6127a769c1d060d8a2d6850098b63562dead6d98bf61df380b1474ef8a5a5aa7fca7606ea4110da243c9f99fe8111e2c27cc909620ecf31a288e2258a756348ee53d6cca432c364cd2350e3188a84c86ac850eb822d50598a376eeee219ca6e40ab45256174b4e2c7b7e672acd440c4057da1df249fd05b8dcdac1d4d3e75e7dcc6cec0833a2f298323a3649c9582875bc7692738021a267043d420f41aaa2ab2948591ffa4634693bbf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127050);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1748");
  script_bugtraq_id(107619);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf36269");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg01089");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-pnp-cert");

  script_name(english:"Cisco IOS XE Software Network Plug-and-Play Agent Certificate Validation Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installed Cisco IOS XE software is affected by a vulnerability in the
Cisco Network Plug-and-Play (PnP) agent. This vulnerability allows an unauthenticated, remote attacker to gain
unauthorized access to sensitive data. The vulnerability exists because the affected software insufficiently validates
certificates. An attacker can exploit this vulnerability by supplying a specially crafted certificate to an affected
device. A successful exploit allows the attacker to conduct man-in-the-middle attacks to decrypt and modify
confidential information on user connections to the affected software. (CVE-2019-1748)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-pnp-cert
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f246a7b");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf36269");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg01089");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvf36269 and CSCvg01089.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1748");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(295);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

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
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.7S',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9aE',
  '3.6.9E',
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
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SE',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
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
  '3.16.7aS',
  '3.16.7S',
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
  '3.13.9S',
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
  '16.6.2',
  '16.6.1',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.5b',
  '16.3.5',
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
workaround_params = WORKAROUND_CONFIG['show_pnp_profile'];


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf36269, CSCvg01089',
  'cmds'     , make_list('show pnp profile')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
