#TRUSTED 7887a4acd6706324abc1a7c149c7e619fa395fb3834ba85a560c120d457dfaa11e1a3a68269320e99505e677f56d61272ec0a2284bfebc8381f7877dc7f2fb7f3424d32250dc5d719fd17ae12dd3a4b2cda1cba22e83134e0cea2d8aaf02703edb6e8c32dad3bee00e783c32185a2d2724fb56c72354e8b7784654a6ffad1402044e1e6cb91fa690b3d38d6a29bffad490f89bab4a3df74f4ad3ccf069f7629933192dd97b2fc1d1522e52ceda646408e20acaf6b5ff196fa36e8e375c8454934b00cbcb5fe2387b1a1179df0673cf3561ea981cab2680c246e05827cc86a2711af5f6ae3aa295b4726f2dbda44813597d8948b73e632a0644982cf08d5b1b2a54ee3e1a062d88484983232b8390aac2a394913d1d56a428a2684ad70ef7f71671fb08c4ca4ff129cfd433b1c9453264d2d7c3a3ac2592f08356c640644c5fd259f0e8975497ef348b4bfc133012fa2cc7d0eefdd00fdfac9a3e56d6a54dc8d1b8db5b09cb60126e4e8ecfb591ac633c44106c2014e8ee524f1fdabfd0815ef85a3183663784c986d851428bfb96538c615ff6567c246972b9f1e98a6339c8358a116b8b1a978de7ee1fbaac1061740ccb2730fcebe11578989e2a224cb4441c99ec82fd78127f59511a7881141e42604533dd5a695b5b326acbac02e9254c625950502836e34c9af774b8eac073c0d6fc2e9c3b254a5611458dd02921008756
#TRUST-RSA-SHA256 57307b7af6d7b414f0acc8a2eb8266605406aa3415a7bbc95055c477368b9ee9d57ed2390aa34b8d23de408d7e1927879c2fa4857046a6559257121ff2080d0e3e81c7216815e58511056afeaafed352d0f35471f1a7c9e6f3e54e3e9b68d8e9683c0e08448345332bec9f3a4815935ec20222386f5f6897d80ad3619e198324678e944f8fdf4fc9257fa16b515c088f5a1993c838126c29d7ec342a6fa76c352f439ea6487ed3a0eed8f0a6cedc49e04af2fc1ad44c003cbf3d30b2a00e87d0bf444f4295723694a8df709bba094b38f91d7a5dc43e6e7a98deb237c9da2d4cc4ee46c765aee8eb53dfd8e5c4b6d75c9eded6fa2be7f9d471a9d9251dd270fd544d0cf5d27d79a22d2f83d2899839c911c9971bf9f7d98eff48d22d8013a44d1eefa33bc3bbfa4c14e7ab892d2dcb3488c0037326d42a188c2b29733cd2385326c9a8a62b762658374f4672ca709bab8be2c35eec625eea6de812f063c5aa6e2960e52938f5bf484c37e2efcb5a36acccc2a0c7280a1789e10d44aee9b64613f1cb29432bbcea58a7d7a20988da3268d0b04510a2bf8a9a11185240608a35cae4d97d7a596cb4a9cad3410f87b60f1218f4cb922d36d14c8c0d793c2c25916964d1909ce1c2558e9b55c2f52788a0ce81a85426ef96e0e7379a2207d4b1ffe79a3a7ec443a0792e2a6719b6196593d84c542db0ff3f47e4664ce3fcf0b191a0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137836);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3230");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp44397");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ikev2-9p23Jj2a");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Internet Key Exchange Version 2 DoS (cisco-sa-ikev2-9p23Jj2a)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a denial of service (DoS) vulnerability in its 
  Internet Key Exchange (IKE) version 2 implementation due incorrect handling of IKEv2 SA-Init packets. An 
  unauthenticated, remote attacker can exploit this issue, by sending specially crafted IKEv2 SA-Inet packets to an 
  affected host, to cause a DoS condition.

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.
  
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev2-9p23Jj2a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00835fb7");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp44397");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp44397");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

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
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
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
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.0aS',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.4.8SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
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
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.6E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.7E',
  '3.6.8E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.9E',
  '3.6.10E',
  '3.6.9aE',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.6SP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.3s',
  '16.9.3a',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.1f',
  '3.10.0E',
  '3.10.1E',
  '3.10.0cE',
  '3.10.2E',
  '3.10.1aE',
  '3.10.1sE',
  '16.11.1',
  '16.11.1a',
  '16.12.1y',
  '3.11.0E'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_udp_ike'], CISCO_WORKAROUNDS['IKEv2_enabled']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp44397'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  require_all_workarounds:TRUE,
  vuln_versions:version_list
);
