#TRUSTED 459030f2c8131eab793b27319b9e90656c9ab4c79f2e63f65559d45f7c4d72b6e9c414490de267d67580e8b3c793baad86452fe3c668b0c33472ecc24abc552c29c893d114b99941eff1345ef2f4cc6fa9d6f053ba0e0c61d72623f74ef83aabe99b8e97a2ab1181d5ee8ff350573d57b4a779ff2c3a604ebf3b27bd0ffeaf994965cf896d85ccfc163c72e0a991c8999599a83d4f7fb3a872bd94e29f6e22acaa21e65c0b04cf2d3e7e9e459ae78813052bb03380415f2652e67d5be681adc05809bd187766f60c17e48521da82f56222b2dc8ed259678114c01110378c757ba6837cb252f27ea0a73c1bd2ddc5d35efec8ad47902366576791348f057f55fef8e9ec6eaa06345b0ecbbd7c7f8163c1005f9773665918f0b50c7e7fd5a426d0705d3232a6a91b3b2fefbdaa25f274bae8e852283555534d0e9b5aec695c14117f868e1c58f276507b9b12e7d8089d1de606fbb2a0cffa1e2d641f18f78e9a7e7431cf1dc0fee412ad0703a844d74c39c6c03a2b278bd59c09a2aabb5020fdaf77a2a4d5f0ca7376a9b379f38541aa8c604713fdf90381530f0af25b2444ec61bd379e8eca804b9a33ae709e070f949c729ba4e7a828a72e5dfde7370018347ba31924d168294e4e50fef0eab65289658887dc2ce7b5842514356a9ba6fb47a33c0122c967c64eadb8e248b887f4e2bd319449655a8920d5c0f6ac98961544b2
#TRUST-RSA-SHA256 09d8f0c8b3ae1976164c2f7b0a9b7f95fc8ee9bcfa6bcae2df5a8baa84cdb3eba2e601bcb0ae981991a39a4b3d3366f134580ee3b7dd421b35002bf777c87cf0fb4329ce55e0079d3351db28380fd97346ef4a2e98c507c1cf59e5dec429c6665cd797f78f9d7f4bd9cbd94f07fbcdd3f3d96d53b134dad8b422319eff78e45cb22b464ef114afbb5dff6d4a66b62faacc076aadc392db1edbedc764f3cbabf639922b25f5e7386665b2401fe714cca269560090f5f09f396518def2cbbfea1fc2f014c7b850b17ae6aa3c82430ab9011767ab9417a58f3eb8f5f6fdfb213bc9c5f539e5081ae2bb2c1a53cd6cfe5ea5510157a02cd7625cec30eedbe49c0f9317b689a3dc92d47421d0f8fe972b523bd29e937d379fb53272c99901e9c5e124a9727c37b0a24924abec22746533003f3acff9c1f19d43ed3685b8e6d4afc04c29be2a2f9ecc80a6acf7ca2630d78db110350b8ccfe991fa8a3f3cb470202753d2ce566fd08b5fb7ce938b140c13d3c0bcef031a211cb20f0eb276db30653d974986f906dbe983461641ce215f390235e896afb03bf7c9b789a92cb2481b8dad3cdc6d049f12dcbdcc99ba2ff6e976a1e2a04bf54e6256a60d5614420e848d41a952cebf18ac0d376ba342a9bb251df20cba18ae94df6eb295ba293aa908c6fd0d527e0004120fb4daefc10b1116e6814419265a14a77d127b47640ec01e7031
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131165);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-6393");
  script_bugtraq_id(93196);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy87667");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-aaados");

  script_name(english:"Cisco IOS XE Software AAA Login DoS (cisco-sa-20160928-aaados)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Authentication, Authorization, and Accounting (AAA) service for remote Secure Shell Host (SSH) connection. An
unauthenticated, remote attacker can exploit this, by attempting to authenticate to the target device, causing the
device to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-aaados
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c26f7fa");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy87667");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuy87667.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

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

version_list = make_list(
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
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
  '3.7.1aS',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
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
  '3.10.1xcS',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
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
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.2bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '16.1.1',
  '16.1.2',
  '16.2.1',
  '3.8.0E',
  '3.8.1E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.3bSP'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['aaa_fail_banner'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuy87667',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
