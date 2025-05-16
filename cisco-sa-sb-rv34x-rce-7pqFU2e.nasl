#TRUSTED 5a32f986de17d62b1c1ade9c23f47a88a1339b80232c4020c611545da3128616facf1491263b8e55a54bcee828d85d26d275041c4cce728627636e428304a74c7a57f901ef30e17df082d879f417f5b014f67476af8ee5c89520937eee1cfe6d41f0c02a8effd377b2c7fd0f6c34e3a8e1274e9bdc5ab9105931dbc679df1e6c5e256d040ea89ed34b6e4606e0fcf335d40348eeda65349395a62af1d142198015c068c5fd4dc431c3ccdb3a2b233ef5dde0448257d2187df20ce0a3181e06e2163ec13b8971dc21f22a2fc7e98a0e3bb20b50f2a4806fc909910d3bd0aae8fbd631a7e168b8a188a079886acfbce240d27c81523be8c857322259f55e0bf48652f89f77ef91e8e1b06520711c56611345fd5a74b909ae3f9b2d7aa6199e501b308643dc7a58a45abd598ebf68aad9805f7bd86923a604bcd5854183d0c57c2df704a273c4baba074d8da2b962dd0676f1670e183af9712ae5d575c872291c3be7f6e83c148d1b314e56c76ab5336a5b94b657822a22787f81a3f0340f4d452d11185d4044c93cbee0f1af3853a8ae4ef5963f20fcbcf095010b1fd22f4170e642295861bff9972911739c0920bc48ef4ef53c9c0b484eea3f2aa623e8d5f3a2dca6c54bf0822adf6b0ce29287731c2f82b335bad67a76dfda6ae67c0bba854489a52759a89ca32dac153f53fdf10e2ce07d86609ea084b5e170770705ba5b62
#TRUST-RSA-SHA256 32a4ffdbfa472a0bf6d6ba62356cfb79c414b715bfe8069dc51bb44e43a0cd52fb379f1bb316f9a5267754545e3a8f6c88ff76fd89d782d1a5478ac0617e9771634a9681cb061ad9c1cf12881a8ab3fd59eace17962496d4c51e1edf11c44ce8b917442e8f78f9c59549b95e24d4a00c7205e103d75d3f29a5bb525f2a9382f537294e61ff9627a05186bd471e923fc31eea61a29bbff20f87eb1fc4d66223d05c647bff6a5a8311f355e018ba8ce978b41100c697acaade94653f7d0c3cf3dede59c9842198b6d7da53715e6687e02eb9756bd0331b73e7e75aba6df2e8776ad532c491c4525fc96b1fd0bb9328cbda794401d61c1f053a4da043cd2b24d1f6b13e0b3d4acd8babef17bbce3bced8d9159e1163ee3f95d2d502aaf6f91e17dd645aac73d5bdcde9bc83955515957cc2d64c12df41df73d845167b23995e31e618d5df476f2a8b80cfa040c17343dd45347990f6a55f5590f566769c91201eb6205c8829939a0628623c3347e0fd05ce49e09ef105474502ae3d2334b64ae9ce6f603051fb3de07d38044f7a40b854eac3056a77b28bca728ba060b4dd907d7622ddd7ee6a1d6862d7cdd1f00675e196b37f091e8077746ffc9532c44a8df72008815cdc543413093925680b2893157bb868d896265a30d80206ddc1d0682b85fd3bb65b2a834459956de2101492731bf699cff878c312d8d553fb0c1a369b38
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208091);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id("CVE-2024-20416");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk32012");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv34x-rce-7pqFU2e");

  script_name(english:"Cisco RV340 and RV345 Dual WAN Gigabit VPN Routers Authenticated RCE (cisco-sa-sb-rv34x-rce-7pqFU2e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco RV340 and RV345 Dual WAN Gigabit VPN Routers Authenticated Remote Code
Execution is affected by a vulnerability.

  - A vulnerability in the upload module of Cisco RV340 and RV345 Dual WAN Gigabit VPN Routers could allow an
    authenticated, remote attacker to execute arbitrary code on an affected device. This vulnerability is due
    to insufficient boundary checks when processing specific HTTP requests. An attacker could exploit this
    vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the
    attacker to execute arbitrary code as the root user on the underlying operating system of the device.
    (CVE-2024-20416)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv34x-rce-7pqFU2e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da02c7b9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk32012");
  script_set_attribute(attribute:"solution", value:"There are no workarounds that address this vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20416");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(130);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv340_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv340W_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv345_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv345P_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv340W");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv345");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv345P");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  
  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (toupper(product_info['model']) !~ "^RV34(?:0W?|5P?)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

# Using high max to represent EOL product
var version_list = [
  {'min_ver' : '1.0.03.24', 'fix_ver' : '9999.9999.9999.9999'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwk32012',
  'disable_caveat', TRUE,
  'fix'           , 'See Vendor Advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:version_list
);
