#TRUSTED 068aabb14c895c9f36489fc179c3aea1280e771213ea3e2ab149094113dc929c675d38b3ad702dfb3dc100af4f7a96d8c2ce4d7deb7601b0ead0abab7ef9321343a8630bc52bb4f4d10d3e7738fe9a7e09ffda814eac7097da5738176986994f95937a203f65a89c7b52ed6347396de0e92fe5a815db56e1095f57d43906edee68b68f00dc5ddfc944fb969b6650834fe28060032ca30dcfe9c97111a87ee32313a27f473657df56147d9b081efd014881ff861b8f0b9a3c9943e4ed06b64158e20ce66262dde6527a92d0ea120534501102b70d93b1a3c7ce300821cbc191596d8d2ed132ff769677661b9f13fad93591b7a474d8c9afaeab170f1aee673a1b5aa4ed5bc1b258b31091eca915e794c84824ad15e48d46155c9a6f70279d9eae040e7d17b8758bf034725b122ac526e1ced4a5d501e780a4380065e6276b76bc2ce0937466987d0748f4af29f0739461d58e56421f5b7fcb15dedef16e913f835ec138fd46f48521ce3749869184c8e7a4d962fa5962a29456b9f5160b6be41a923c4aa274c956bd0c2796decc4f51ab4541e1869aca1e002c8d874adc3408ea27fc744ec978a325d53ff71fbd2b2356f556c5f6f9148ed60e0e8d8f62627e40230e0289c6ca3d97eddb470b21ccfa9407ce8b451a2142f78872512137fa29e7aa4a30efed6e6cce7fdf3199d769278d1707386be5f8a0a098d81341c7734191
#TRUST-RSA-SHA256 a238a4bbeb39920966bb20bf3ccbe122d47513daab8e7616d0d7b5f97ed5012b07539349b4ce07d5d2b51e9bb3de8d0cb8a3087b79282b077dd905c7953b79b7f9d454dfd6482c50875fa9fd6aa568521bd0cc95e6c612095db0f0737abe952ffb0891a48c225b5543db1efa95a801f771778a4e505075c3e57ad476b84d30acc1a087b505f4e228ed013882386a04116866ce7cbb6351da52367ce2662f66a5386d93202f9537c6793af4d5a900340b6eaac1e7bac4e96d36626aed2fc4f3264c70fb043fc408f58fbd70d55ffb6aa355296915e941cd776eafa7b134ba9d860693f7177c95179f88fe399c4173e924296ee81c9025405d6631cad52fee391a5956ec6d39fa04667148033e06abe9286c266587bbe66264ab318f4b3c6543452b46ff6c1f5f3c0fde747cfc09248e7ee1413cc976c384ac08508a81f2d7765b990d48d9c1af3e7a37071b8a12d51461e2f67391da05cd66deead4c5ed9fa615c0f8d134b1e3d56bfc70e42de95e70a14347acbf3b22c030239d62fe2cac19693b340342e1d568fcc21a3cbeff1e35216d2c1729d418134769b3320eb249d50c79f79aa332861bb866a4e475b604fecb6cf425c6e93a069d80c0cbe89db62c1bee9097d0b9b842ef01de97139b381ba70c169eb2ed3b331cee3c570b7f80b51e029b55b71c5a8bd4907180d5a0bbe50214fb69c10dedd9f7d86370f0b1f2349c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132698);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2018-0189");
  script_bugtraq_id(103548);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva91655");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-FIB-dos");

  script_name(english:"Cisco IOS XE Software Forwarding Information Base DoS (cisco-sa-20180328-FIB-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the Forwarding Information Base code due to a limitation in the way the FIB is internally representing recursive
routes. An unauthenticated, network attacker can exploit this, by injecting routes into the routing protocol that have
a specific recursive pattern, provided that the attacker is in a position on the network that provides the ability to
inject a number of recursive routs with a specific pattern. An exploit allows the attacker to cause an affected device
to reload, creating a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-FIB-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9af64740");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva91655");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCva91655.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0189");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Converted from IOS versions found on the BID page to IOS XE versions, according to cisco_ios_xe_version.nasl
version_list = make_list(
  '3.5.0E',
  '3.6.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.0E',
  '3.11.0S',
  '3.12.0S',
  '3.12.0aS',
  '3.13.6S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0.1S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.16.0S',
  '3.16.0cS',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva91655',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
