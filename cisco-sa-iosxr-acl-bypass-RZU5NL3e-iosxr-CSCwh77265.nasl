#TRUSTED 5ce7bd1ef8e084885524880b611f38639805045449952d4d428faa101518e058cece6b284158bd5478104be054ba0f0f6ac2785d519efea521c0707afd6fbe87d1c598f1280cea8368191965c95abc3d35a4dcb594a5ffa93eec0e722e6d4cb1295d70d87ad01f8c37a971a3b4cfc87a682c12c1332173aebca7f1804647b97b5c6846b3ff77ab0876bfdbfdcd5e5f957885458a4a76e0fb874bacc077b3e984e0c6f24711b376195861532528a1ef009fe80c741317e0f52f2c1cb702ed02469a23bc933be55fb118970d1915c69eb68cf033ba73f33846df72cfb763172f1ac99c9f602a335141cd914836600e2fb2303299e4edb316b4e06c56f1f8fd92eaaa4308e1974a6b4555d6e7a9473da22b917af417b055937861254980895f58d87cbe91d30d3d8cdb59287d61923dfda98cd2f7db4ab38e0dfcbb14f2c5e6bc054346d675d947c2cb12b1215d50036fa8955730b598e38b77fbd3a89f5a1a67cb843f35236a51f937337ce69b596c042568d0c6321a5bc582b39bd2a01dece20ebdf6d67da0ed073f169a20c82717dc185e222162538738c55a5ba9d5951d8ec08bdd80d951a093d20f8a878bb0731e3eb8e4c93136547e6d7c57684c593db14440115acdf917fa02cc6f378c1b842067a33893645d7a49222851959e7ebdd1262f0bc81585c16a2c8b5745366c6af64a5af69fcdcadb7295d0a116d7da5f18b1
#TRUST-RSA-SHA256 6860522c5ec0840f65e893d70130ee5595aed81c6c6745469312cb598fea202fdfb15af38f5983d40d1620865cf82bc3fc0886db2101de6bd86830ece1ec1f439446b70a253c8ddfb9a00b81f0b41135c73ed45c72b051ed031448742efea1a21ea472432198239c7f84e7875dd7ec3d210c38e8f1bd9830c146843a03ae8c8573520c150c708187406140048cb8020ae1afe9c29bb8b0b3f336a5536816527505cb4a40baf9755b04b736390d0d66a8349c96aec68f488b0c1f9df45bc398180a1bd4afd38b5d2dbcf7678aaecaaf7e134396ee84d79539362191d72ef5c015bba0ce9caae5d71868c1a68b909969c6aa0e8d638244dbbdf4d734c881ca6daffd0599b7f0ccfcf48eb4b4a4e220a721d8a74424b422b5f0754dc36f548a8f3fbeb19ba6f8e47051ec483194d973d1b2218f4dffcb762554f0db32daafc670aa45968868c4922683e9d0047a6678c84d802942c32f0d0c905ed2620047d6ed345b082aae00fe0a4d2e2711a60930d5313bdc69cca65829b979962cd9993e5942897a0c09a9ec86bae5b0f9ac65a93f1104b61c8879f3be59571f16a3c79523d4b14c250d0e20eb19c59ca32fb05999cb909062b6af5d43aa75f8057d828fd3b76bc28568385ba35ff2b855844a84cc3a6c1afa80903a63b752437aec9342598ba85c46d02c13448d0e96bf8ec245694d60cb709c0e239ba0de62c9396d57ed9c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206039);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/22");

  script_cve_id("CVE-2024-20322");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh77265");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-acl-bypass-RZU5NL3e");

  script_name(english:"Cisco IOS XR Software MPLS Pseudowire Interfaces Access Control List Bypass (CSCwh77265)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the access control list (ACL) processing on Pseudowire interfaces in the ingress
    direction of Cisco IOS XR Software could allow an unauthenticated, remote attacker to bypass a configured
    ACL. This vulnerability is due to improper assignment of lookup keys to internal interface contexts. An
    attacker could exploit this vulnerability by attempting to send traffic through an affected device. A
    successful exploit could allow the attacker to access resources behind the affected device that were
    supposed to be protected by a configured ACL. (CVE-2024-20322)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-acl-bypass-RZU5NL3e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7ec5d32");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3206828a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh77265");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwh77265");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20322");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
    {'min_ver' : '7.10', 'fix_ver' : '7.11.2'}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh77265'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
