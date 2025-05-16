#TRUSTED 24c6cf1be88e1e9d3c24468ecc66746ac92210d9ce4871bb747e8779ad889149a034d73f342b67c0b99dbef365a1183058b58ee0ac70b449e41c8bd3a122457343dcbedb672e4958c88843289e15c119488b2c8804225582b964575d746811fb3840e1d6664dd134c7e0a2613f5956ddb6a39d7c79ba42c1ecbf076838bbb5b39762d398fb0cf3858f3c6c55c87c2b5f862a5e2f3a88345be99dea57e2925a91af15bbd38ad0e38ec1ca55579082ac951a33ac4bc4638d809b0ab7f68d6ff1ee88a709a70ec1d47b9cd41ee2d52ff7b0c8a61fcb6b6c0c2f7eecfe1405c1877f581a75de2e2f7ed1ce2331938cc33e284e66b4c44cc0c0a1c7e6253bf20f45c212e25eddd55063520a1fae82958ebe79e56dd6a958a8e1ce142a7c9fbc68ff91612657a3c78e47a09f36c9ea9b807fc60a339cd4d22d2bbf891c1eeb983bce0503b8a3a0a7ac44ad2abc6d396649c773857f2ae945ace6302bc4062fb4cb32296c4e90228358ce4bae4fd0af72351b6c0f88a7497bd2d36dafb19095c632eb3901ca51fc40ecaeca91500e5055985ab966659d4ebb4e1dcf38bb4b5128ac5f0521111600659bf553a407a5063153d415815ef5716d41c75fe8b19384bc9c93a720407f68cb629afcf99d7d14f95ecfd4732d5aa76c6c0d87e01ef4e17506580ebe082b75ea8035e6cfa0b55723c5c8a4da5498210d62a7c6f012f7ce7ab5523e
#TRUST-RSA-SHA256 25e8b83b5863949e2c54e33115f1e77636a00a33724fcf57cf9280319ce0c1fcc5f02d2a9b5c8ae2f04e373b605275c8971470b7979112222c6dc4b76ea9afa2bfa46cc4fb6e199e21206f9a3ee6214c899bd61a9f1610fdf8826af8d8744dca22cd36b51c5b39980f124dab69ac91b62bd3ae24e6e13ac6b0640173203ac9febd7f3964b6fbe0603b28b9377b7fb489ad324298e8d14d11bdd1ce632d7dbe87284bcc1402b7dc5527ac7570ce0b1b928f862a2f2f19e0e76403b07196db924870b553021fa6cf7578b5d54d9a9561b80367366d7bc428fde48af55ed6f1b7e5e238a7ed9540a0333753e3d87de962c04084c53e9242a0c4a0fa92ddd6152d667cbc6885fe635bef4b75b397357362bdad45b80b16e6ec0fd61a37febbe33a2cc79cc2559c599a03b25113466fe3442fa3c1dec5b9bf2807cb73575f3bafeefff0be1745f13fd865765b32c1e2a2a241be6d5e8243261c05352fdd8390dc816c31ce6c17372f78f7993ac7fe69e98689937102351fd28de44167218a074e3073e011dc854276aace9af065afb4433dd6a95d9b94358df362aa386a4dfa7b4526691be150dcb053321499dcc2debeac93cb6615baf6afab868e2fda2b7a758c3069b3e4e03a460a5005f7745649d7e75bdc309a95a022e318dbc4507112eae92dd047393808f29d2bcaffa459ab16607af03105d2f7fa613d5a9b1a079dd59f9e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215124);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/07");

  script_cve_id("CVE-2025-20183");
  script_xref(name:"IAVA", value:"2025-A-0082");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk58287");
  script_xref(name:"CISCO-SA", value:"cisco-sa-swa-range-bypass-2BsEHYSu");

  script_name(english:"Cisco Secure Web Appliance Range Request Bypass (cisco-sa-swa-range-bypass-2BsEHYSu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Web Appliance Range Request Bypass is affected by a vulnerability.

  - A vulnerability in a policy-based Cisco Application Visibility and Control (AVC) implementation of Cisco
    AsyncOS Software for Cisco Secure Web Appliance could allow an unauthenticated, remote attacker to evade
    the antivirus scanner and download a malicious file onto an endpoint. The vulnerability is due to
    improper handling of a crafted range request header. An attacker could exploit this vulnerability by
    sending an HTTP request with a crafted range request header through the affected device. A successful
    exploit could allow the attacker to evade the antivirus scanner and download malware onto the endpoint
    without detection by Cisco Secure Web Appliance. (CVE-2025-20183)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-swa-range-bypass-2BsEHYSu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?302de8d0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk58287");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk58287");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:secure_web_appliance_range_request_bypass");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');


var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [ 
  WORKAROUND_CONFIG['range_request_download']
];

var constraints = [
  {'min_ver': '0.0', 'fix_ver': '15.0.1.004'},
  {'min_ver': '15.1', 'fix_ver': '15.2.1.011'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwk58287',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges: constraints,
  workarounds:workarounds,
  workaround_params: workaround_params
  );
