#TRUSTED 222329a931c63e1326d049ebdae25aea5b919935897f07880c4d850d7b58a9d1ba9fb2e89496dc650e84997d8c8008bc5d067353de18178463c95144fcde309b6b8a937ef0422bf7d87677099be3db9d43a5315379baff3acaaa1d7544ab089828fa76f38c49e7b3a9bf42949103a3c06bccb6f0166be7065f89e6527e05a9f94fbe4dace69efc5b35973939c7ca6bdd1013edd38474bbd071e5cfa4ad8430ffa83a8fd4527e05e21d150f872dddeab92e90ae2bd4d4a6dec72de37877ecdbff9677992e91d7c9ca8a6ccdb4bbfb943c59464f1c383a011af650aac113e7480d14ba14b963e1694d422426ed90bc4cbf1291fdecca6c08b3dffc302b0c79f58a65d9b8e584a22fab6828334887e796941ecedb50f544c140452dc56ad74ef7585e571f0e42ef09e431ea85848bb16f98788d437baae72d2639872a31e4b4588438e793cfb12f2c05b1984dfb6773b5297dc6eafce45fed21bf26fd9682fa008ddae90ccaf076ae8d4146a5710066df5aaa94b0e042a7ddd473b2e99cad49e369b63a61b67f6b328bc6a51ed433c74c79439af77f32dcfce1420270b6f61f9b0e6516feb80900dd6e1194350df35682988a47108511bbcd667d8acab0f542f1f7a43416c4312ae5b626152151b8c89cf851c992fc9f5a5464b1cb88fc162166ec1be9ea14c553407d5f429e6af56641e31bd4d17c228e07721281e983819f3cd2
#TRUST-RSA-SHA256 22e80971b3d0c1b804c90e699399021bd4d95a6d89992b31b6dd8fa2e45eafec98fb489e0fe5d5d317a91769887e25fb87678a157bf9deed197448a8321004bbb9d9cb43fd93cfb6d4e0cbc2cef92bd03d171a6a367671824c8dc5020bb47e85a00e87ac746c36be8337de43269c68e9158129a09900264156f3fa92a89c2e9df53b06b87251cda343d87bf2809589a594dbd4c72933c7f5fc4305a69bb1afe2f06c1dbf63452dcd7d8f097e0db6d5cd9bc8d087a6e77be67a26efbfa5750a6e271c931d7c5437e284284ef80c8640a784b39fa67305556df246f6373df8c4fd8a2de82901bdd9cb9bb43e778808b7c2a24cc597e3acd9fb90a0f8baa5b0626db212e76f991fc565b30628d84b1651ffea8076ae4bfe3c375ca6e767cd9a2c5d17e37a0ae781765edaaee10d41d12d2be8b74ee73419e1e9967805b181f224cc165477247e44ba1ce910e99a214ad2ddf960284ffbf344b2cb42de90a20750c3c6166b542555030feaf8fd511fa09294a1a5e27cb20b7f1626aa042cb653bfd57604b01ecf1e819cd8109fa868e8ffb83fda90d4f7322c3406a6c065cdea56617026a22a5f2509b1ec06c06cfa75afe46bd7e1c44ee6ed73e600acaeabc811cfe7a342f7585a31723d155417b0afe3c01e20e5bcf2488ff4c1585667c54993472754e04e5ed7aec72a6d1cfa1aeb662e4a5af36f90b903377edcf9fb0b78a9db
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124061);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/11");

  script_cve_id("CVE-2019-1827", "CVE-2019-1828");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp09589");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp09573");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190404-rv-xss");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190404-rv-weak-encrypt");
  script_xref(name:"CEA-ID", value:"CEA-2019-0212");

  script_name(english:"Cisco Small Business RV320 and RV325 Routers Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, this Cisco Small Business RV
Series router is affected by multiple vulnerabilities:

  - A vulnerability in the Online Help web service of Cisco
    Small Business RV320 and RV325 Dual Gigabit WAN VPN
    Routers could allow an unauthenticated, remote attacker
    to conduct a reflected cross-site scripting (XSS) attack
    against a user of the service.The vulnerability exists
    because the Online Help web service of an affected
    device insufficiently validates user-supplied input. An
    attacker could exploit this vulnerability by persuading
    a user of the service to click a malicious link. A
    successful exploit could allow the attacker to execute
    arbitrary script code in the context of the affected
    service or access sensitive browser-based information.
    (CVE-2019-1827)

  - A vulnerability in the web-based management interface of
    Cisco Small Business RV320 and RV325 Dual Gigabit WAN
    VPN Routers could allow an unauthenticated, remote
    attacker to access administrative credentials.The
    vulnerability exists because affected devices use weak
    encryption algorithms for user credentials. An attacker
    could exploit this vulnerability by conducting a man-in-
    the-middle attack and decrypting intercepted
    credentials. A successful exploit could allow the
    attacker to gain access to an affected device with
    administrator privileges. (CVE-2019-1828)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190404-rv-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ea0bf3d");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190404-rv-weak-encrypt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75b1813b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp09589");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp09573");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvp09589 & CSCvp09573");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1828");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 327);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

vuln_list = [
  {'min_ver' : '0', 'fix_ver' : '1.4.2.22'}
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'fix'           , '1.4.2.22',
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvp09589 & CSCvp09573',
  'disable_caveat', TRUE,
  'xss'           , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list,
  models:make_list('RV320', 'RV325')
);
