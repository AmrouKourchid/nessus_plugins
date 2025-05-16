#TRUSTED 4e4833d16337e939d048720a2fa0ff3ae142297fa3957573f88338010c7a8cd7aa372d626930578077d92c6801ff1403db768c39323acf1e3d51e69a4343676417874bc5c96f1a604fc23b022bea2c6cc90e74fcc1925e56eb8efd7ac9da8767adef7f5dfc8d2865d162313102360bdbc57d5d4d826992b8b55d77c62a538e0b9bdc18ae0afb65b4edb2d2f330857390c93f1f2747c3349dc82691e7d72f9de8b9bfacdd2d828fac6c08d1d513764a29e384acfc3c2be70740db0cb9b2ca1435d7cd079e43b6b3a47828da42e12839f1ff1fba52751348d31ce806c491744563ed3bc6bd3ff3d3e17ae6ed97b28b334b45cbf53a288c3427dbb54486cab73e25609ed7b45ad8900e93583a428e347249d2152c5c0692e86a4b8cc9485483607337ed22063cba84f3ccc18899c0a5544b9d85708b6df62879c348f4b9548485a582d51181a713e2faf3499bdd7f4b0a9c1d69da3b418e5d19034f27788b28878edd983dc2cd0887b86e7d7a8a092bc53f20431e83791fea551a4878d6cbac5fbcc0c342b2eb4bf855198b801396472a3713c1ecf905323914531eaeaf867834b6dda8c120a5afb327763e7560b0410b7fdb83e4ef4f926d9ebfb24e2458ffa6d0c0d2cf64eb211fafea4daf7d6653c04ef61d8bfdb8804ee824fee7b5c68e375dfda67f3aa62c4ac4edd22b35e913b9b8d02655e55631b7651b6cbe625cbfede9
#TRUST-RSA-SHA256 8ab45d7e26a21f29c18699485f577d522a8aadfc72a206eb9ad2f8b9dde78fef31ec0fdf6f27067de9a9315806562fb412c74a052236d6faef99de930baf6867256fd1ed32e21174cb5294701588edbc721f5c0960933aa7dc101915befdc0b9436a58129d5e2d8be1764ee907beaec671d76d1cca771936d105de196a8c44425b16c141f703f0ef9047907bcb5f56cae8cb484dd479d57fb6a675d8b3ad5286ec92ba1a48c62afec7416c56e1dc0380ae2edaee29ad92b8e3689b3ab803181f9b60e6e1eb2fccc3af4b0ddbe80b7d09de2edc8ddbfe66abff0db77bf75bf5c68e7d2c45f765815979f28a9c40eabe8748a1652f3b01d778266785d70731e3337058e210e19bb27d880d77bf7900c90298ef8a500decb156756aa9b7dd25e252d1c94ddbf4d5ab8101283371cea6c0dd136979e9ff42bfea0e43b09d802d6fa0d2add404c75b1a24b490bd8cd46fc4e38f4d067ff742881929e226fff480e7e6970cc840f8fe883f3dc390049ad0d6668cfc583079b1465420935f94ec7f96a44a1bc79787c12eacc4ec8f0026b4c2bf50ed220472fc763fe436557b2dac67d78f7c1d90b1eb679445e2adc7c1fdc02c895411fa28a02b1d54e55f28b521ea8b272c335a9c8abf503078457c6e2167793d67297bb7a8ce13bd15834749fa4667aa13958dabce469cb5ae1a074ee9f21f2ee462230dbe5c720add6cd31c80a704
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216072);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2025-20180");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwn25954");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-xss-WCk2WcuG");
  script_xref(name:"IAVA", value:"2025-A-0082");

  script_name(english:"Cisco Secure Email and Web Manager XSS (cisco-sa-esa-sma-xss-WCk2WcuG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager Cross-Site Scripting
is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Email and
    Web Manager and Secure Email Gateway could allow an authenticated, remote attacker to conduct a stored
    cross-site scripting (XSS) attack against a user of the interface. This vulnerability is due to
    insufficient validation of user input. An attacker could exploit this vulnerability by persuading a user
    of an affected interface to click a crafted link. A successful exploit could allow the attacker to execute
    arbitrary script code in the context of the affected interface or access sensitive, browser-based
    information. To exploit this vulnerability, the attacker must have valid credentials for a user account
    with at least the role of Operator. (CVE-2025-20180)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-xss-WCk2WcuG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cf44498");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn25954");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwn25954");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '15.5.3.017'},
  {'min_ver' : '16.0', 'fix_ver' : '16.0.1.010'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwn25954',
  'xss'           , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

