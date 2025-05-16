#TRUSTED 730b66181f7c87c0faa384ecc3c282e988ae8f009b24454df062166f369c8dce684fc3dfad723cef6fd74984812a33bce92c7111df74e26bebe54e2099b961bc08a8e9774d266ae8f0a57764046de28439230172c1d4bb44e8d0bb237b0071f3e9ec2077c3f09bcbac84f93ace8eb5988d155337a79ed0843b542991d21c731023b06446b5965bb9176fb29723409fbe9dc6803cd3d67030ab2c602fe5c58332a33cdb9f149d7223e91350788256f1fe7de15f06f34749215705b9664f113d6ea34b4f479cedbb15ca658e8b6c39b6a32d84894a47bf770c879b244d9c31a52707528062f6e6c9ce5641db5458e6b2a264e0767d4cdf30f5d0cac4925d7bad0a9f6c515c3a2337ab2915841e5f3420b7235543280ea29749f833bcfacbd3c9e3780d9953cd11a2c3ffbdfe5020249cc04e2aae684d0801cb5927dcd3253878aab6f6a4d24be0e937014e7999c72dd68903e86e2395f0082078e5834957556b098a6a2f401cc8160890a701cf59ae55af9b2f0ed439a4376a4aa71a34985975197f9b78609d4a26e8bcbfd48439b60173bfa84fef78d028cec242bbc5b7e55054434e6ba0f26ae7996a05fe51a88e8f214829b28e26ea56cff7e7c18cb5c55cfa6405701113c4ac299d415aefb3f8dbbd3a129241cffeb19d6c0660378a234295d2826dae3086c04ad64746131651870fd2c4c38a835a86b2cda997e4d8625d3d
#TRUST-RSA-SHA256 35e39ec0d8cb788a0bd96639e01fdacd2014910e77184766d59b4281d6c37090f718250844fa0e35bef7ba5645b3c3000f2ee38b663989ba6b6b9a4b6595be0c5f493c0c54114af013d380ecd2042eff21d5f18c8d268a65fddce9c173060d2727c650fbc7d9dd30b3f7fb4d77704912580da29da3c7f51bd3a9dbfc63983109ceb73e8d4b888a86e892ec968edbf6bfb86a018b8ab366b20128e04507a3a4a4c1875bac7c964b67f8242403ee69a048cf8cb0334931a2072ff027dafbba1a293cb01edcb527f3c0896c4e52236b59226797021db5142e7ed01c4b7a6350867c8ffce2553a2ec84e6afd46f05c89a513d90c2540a26991e3c70b4bd5855cd01e9dc84787866af6465f2bfb8c89fae584a982c11425519fa5d900e784c5401cbb45e199f8c5770267e5befef30c9724a19cec7dd3ac9eba48f3b03efdf0e55513d25cc00ab57f3a488e7d2b3c7ea269f20d6337a8687bed0ddd37ae5950b502d236f4cba204223607674f956026f2f35eac13b19539aaef9971cd098b0c02cf839cd862f8e2726c25935688043e586fe17ef300a56f2b40cdb3041131d54a65f2c4008d330ebb234a3bb484b72f229b2d019f57cbbabdf2c589489e2b9a9aeca181955274e0e3b18a5c8ea0a5ea85de527eadaa3722f6312cef9245f22286fdf89e21423141e676b17f424540f65d4b9e9c49e243bfa571f29cec692a7773c9ff
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235490);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-20216");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk90639");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-html-inj-GxVtK6zj");
  script_xref(name:"IAVA", value:"2025-A-0316");

  script_name(english:"Cisco Catalyst SD-WAN Manager Reflected HTML Injection (cisco-sa-vmanage-html-inj-GxVtK6zj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the web interface of Cisco Catalyst SD-WAN Manager, formerly Cisco SD-WAN vManage,
    could allow an unauthenticated, remote attacker to inject HTML into the browser of an authenticated user.
    This vulnerability is due to improper sanitization of input to the web interface. An attacker could
    exploit this vulnerability by convincing an authenticated user to click a malicious link. A successful
    exploit could allow the attacker to inject HTML into the browser of an authenticated Cisco Catalyst SD-WAN
    Manager user. (CVE-2025-20216)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-html-inj-GxVtK6zj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?916b21f8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk90639");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk90639");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(74);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');


var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.9.7' },
  { 'min_ver' : '20.10', 'fix_ver' : '20.12.5' },
  { 'min_ver' : '20.13', 'fix_ver' : '20.15.2' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwk90639',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
