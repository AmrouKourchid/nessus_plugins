#TRUSTED 26f5252224aaf6b51f35948ba6ae59ed76de0fc85784527e5b90d6ccaec082a5a812c2eb8ba9b0ca60e4e28bc89fa945b3ee3927b709dee9be141146bd43071f9bfb6c00e156736f225e77100e681180d7d211733e8e141c6ca157b274149d6c48e5044f3446cc71d339bc916db76be4896028fc7909705a7b4aa687b3ea876eb0297e5ddcad877cd35c60fb6803d56056ebb06645024857dcbcf8db6818c911296ec9d8369fcd3dd421186eaa2321031794a17039e2ef3b562ff2395b1ce0d833d9318bbab7e52a330f2eb622df9db5487d7d16240ec0502fb01916cb78cea3f1da5fd4ae23d6ced150010b52681cec7503b2db54bd8fd16810a8ac089ffae18d72de842ecd30dc58f62eaf8b98cdaee3577a4e213c714f2df036047d6e6a0a5bba761459013ce0abfc18e84ba2596bd72de90f568a4242993d53a08ae8a5ba3a24bc9ae5af0b3b9aacdc195a95574b477c3a0a7896dc2748e8645860246b23f501a17c71dd4abee5e1d4319643c09fae57eaa4d62137454d51535f61fcef24e70a8e44282ab1adf2f33712d3e3d650c51b991e46aa76cfbba5e99d1c7066ebb0beb1f6ffa90d6d79196499b6c99de0031ecb08a8085932fdb70f0b9bc70b11cca0fc83112841617b73c40fae82b8f74367e2c21ed0a5c286ba503fc03533c0073e08f9f01785625d8f12f37e51d719142ee2feb5067e9bf46c9dfa879d3831
#TRUST-RSA-SHA256 a69c7adfcc56a2f70aa618a38c02e16089d256332b9caab5da288f5cab956144c624e80e8a23541aa1b3960c0df4bf09e0363bc9f2ae4e12b0e42150b81f597881e6417c954d5ed06158f053ae60f19dce07d4208a30d145f02b6fe4ecf56a66d4901b52933ecc6469703f0827f7ab9ea9cdc81cac45697809aae8bc3a4dafe5daaa00b76015b89f1d2040211d57f49e91c50d698c127ad5cb631a1c27f37a9c3a4b600ea5de68809299a952d19c87b9b8b1a2b451d89f76cb6a48c4512537d01544874ec0b9789abe6e019ccd182ca7537bd2172f97c4fea3d8215cc39c6e52a9d1b9342b70a740f4856c6bc6b693247eafc15be8d73f719466174c1778a98995cc3818ce17facdf62430e3617750ee59acff3a04a14a452f7d6727e4d031541b3661223f6e58d02ed0aaea90bd3cb1f3d66367c2b497e432ff7b416baf4748fb0f198d920a899ee827fe2b00fef03ad01e6642cd124ff4d0067801f045be0e9f2f5b2401ae13985acfbd7491eaae397d990c206d0f6628b326e276555e1777cbe90cfbc7ee3d3a5a9f09b79e0337db1f9f52cbf0456b4270b7a54b78ed82e1fe6c094c5239968bc7988eee4ef7e21da33aaeebd1323425622d29f39f14ecdaa6eff677bfdb7987e7ebffba525834e5cf079fa961aabc1852f5a6a5bf7d4ae3ce4cf95cbb6dd73005514b99ef6885597ef24c59cfb7a53aaca63477593130d2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207764);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id("CVE-2024-20475");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk43942");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-xss-zQ4KPvYd");
  script_xref(name:"IAVA", value:"2024-A-0601");

  script_name(english:"Cisco Catalyst SD-WAN Manager XSS (cisco-sa-sdwan-xss-zQ4KPvYd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco Catalyst SD-WAN Manager, formerly Cisco SD-
    WAN vManage, could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack
    against a user of the interface. This vulnerability exists because the web-based management interface does
    not properly validate user-supplied input. An attacker could exploit this vulnerability by inserting
    malicious data into a specific data field in an affected interface. A successful exploit could allow the
    attacker to execute arbitrary script code in the context of the affected interface. (CVE-2024-20475)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03e6e845");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk43942");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk43942");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20475");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.12.5' },
  { 'min_ver' : '20.13', 'fix_ver' : '20.15' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwk43942',
  'version'  , product_info['version'],
  'flags', {'xss':TRUE},
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
