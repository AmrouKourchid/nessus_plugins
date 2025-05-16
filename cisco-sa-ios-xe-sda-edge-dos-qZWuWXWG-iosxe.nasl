#TRUSTED 0948c91930a90af746a03e3fc48f88e667149a51f0ab4489f33e13a7261a96374d74378bb74fbdea64cc8b0dbbf62ebb80c304aad11ccdcd4ada1c7f9f53a0bd45417d30ece66fbf61f7b984a71c731608bf31ae10ca4beb27bb92380511faf5e5986ba5dcf0542cba66906a972da3cca8cb292aa9677246ffe13cff11307c10a3bc90f570ba999c21b06dfa33a71fcd8c18cf34eec5c0071fcf00a816794cc6cb12dcb73fc5ce6917c71de1bd680fa37e25079c528029f3d76963eba4d74ec3bc4c454632acf6e7cb71c29a68ae28478044f3bb4f0345a8cdc6492e35f849147a7ddf5099b13392ac256842f0e00cadb6f1871bd5f5af579dc78aa32f60a1be4a0885fbd62d6d72c909e3ff5b7b350b14af52857761f1d5c6c07bc0e2a001f0c89d3fd959802b5ec817d0c0add64dcff03819c357f59b81b9f548b0f7b9f181eb103538d43ef43a1a5c02fb9bf28d0cee3a920ab6e7d15d5db56658f9433416acb5edd407cb6da5ea14058c264aed0db18e91e929ce652dfc15df80f7ecd7ea52161101351505e73e4896729d067501208bd7bcf25d5184633e1412bb7651e2877481898202bec1dd289b87febc7a1bb0c4e6ad2c5e397380cee1da2fcbef6c81e31c06bbc44aba3caa465046498f3ffe0d41bcc92308b32564b289e8cb6c03b6b82a13d4b80e3e3f02cc5e74b93c161fe353567217fa1254ea7412a73fb446
#TRUST-RSA-SHA256 12d8883259aae62827e57fa2e25c3533bcfc7b4703e4cd7532532f5b5fe1c3bf549084ae66aa6f59441f56e216167b8e41f727be14ada2c2d7f31b67aaf1ff8f4a7fe68cd0d51d8f1fc120a210b04f7322647b68613bbbb2fa35c4e03b7ca62617a61ed465bd6902ceac36235744481580aa7cb895a12cf3b0b02b1ff37f1c0c5efb3984421cccf9b87d4d156ef47023fa9285ead1d0aacce27b32f2cff25d57632a33f4d6cf11387ca8582a04145e701e01e748d2b327c3a9674c734d041ca936c8e3215b36d198177fb9e461834098072c613888a85f6683ab57f206d19097b627bd681b9bb55676ff27ec59b50089b427d3833bed388c7a68a58df23cc93a0abd788cc0213fe68f040d0d7881edbe9f676735d91247e32414dc54f0ea36e842ac11b1852657de90ada7a98fbf0b33236bbb65242119ae406eb34c463a881ab1bb8afe41c3ddca81a8a3e89e926666396021c924c3f5c9082137e81f739caaa6803baeaea128792ddb69fe1606f31671b2b0a55bda94fc4c91e95a060cd045a3f0b5b976079ed488f8691acfd64fdd9419091cc0087627da2a88233e07480822336a0b07022422749b66018e08c8298d340596253c17154638ae325899270188e1eaed53f0321022a0cd49390a781c62f1fe6125768a761fcb121a29f29b1d20d56f982311c3d082da8e61bc490399c5622fff2656c20c060dfa8e1027d2df
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192622);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20314");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh41093");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-sda-edge-dos-qZWuWXWG");
  script_xref(name:"IAVA", value:"2024-A-0188-S");

  script_name(english:"Cisco IOS XE Software SD Access Fabric Edge Node DoS (cisco-sa-ios-xe-sda-edge-dos-qZWuWXWG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the IPv4 Software-Defined Access (SD-Access) fabric edge node feature of Cisco IOS XE
    Software could allow an unauthenticated, remote attacker to cause high CPU utilization and stop all
    traffic processing, resulting in a denial of service (DoS) condition on an affected device. This
    vulnerability is due to improper handling of certain IPv4 packets. An attacker could exploit this
    vulnerability by sending certain IPv4 packets to an affected device. A successful exploit could allow the
    attacker to cause the device to exhaust CPU resources and stop processing traffic, resulting in a DoS
    condition. (CVE-2024-20314)

This vulnerability only affects devices that are configured as SD-Access fabric edge nodes managed by Cisco
Catalyst Center (formerly Cisco DNA Center).

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-sda-edge-dos-qZWuWXWG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d31ae91");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1da659d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh41093");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh41093");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20314");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(783);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var extra = 'Nessus was unable to check if device is configured as an SD-Access fabric edge device by Cisco Catalyst Center.';

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.9.8a',
  '16.9.8b',
  '16.9.8c',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1z2',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '16.12.9',
  '16.12.10',
  '16.12.10a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.3.7',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.1y1',
  '17.9.2',
  '17.9.2a',
  '17.9.3',
  '17.9.3a',
  '17.9.4',
  '17.9.4a',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW',
  '17.12.1',
  '17.12.1a',
  '17.12.1w'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwh41093',
  'disable_caveat', TRUE,
  'extra'         , extra
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
