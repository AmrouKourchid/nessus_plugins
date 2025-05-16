#TRUSTED 27306916734e25071a73e1cf29e150a78caee0d338ca122a0559b9c209462031f771de3dc4649dccb55322f4002a26efce68bbf7a09777ce9133ad9db0339063e677c269d5c3fe0149d1625b7607897834421b548d9c62f14aa9a067087b585273d6e0f8f383e3556a3334c58ed21ec1c51544267d368a5c2af597a9b3d985c91e3b840a6d64432850702fd4623774e501ff2eba689dc0d4e271c52e1c7b1b1e963ee655ff694b1f844153bf90753043f81db4c67dc6c53b9cf6c611bd5d459889c4cc5664eb4a7614660789107cd6e07258d7b24a6d305ffb4d51c11fe88259fe0efb266db1d5808054856749d3d8aa0e19269e70578a95107eefc4fd5e60e29b506720b697a968d8d2f60475389cd475f663b6f1496d82a0eeeb02d407984d5d1f6657550d57ce9ebdf4a5b80af011b5aa2f760afb18db29434d017b8b816f849aabd9825e148008db5902ca0e83da3e08ee088fe38844e73e76d89633c5067aa25d10daec916fe37d2beb0cd900a0e39f31c71ab97be28b7c885d53eca803c4afc149aef61a6e5fb5889275540938d54be2d89ab4570444ae267c714116e12317055ee6258c22b5bb28cf873455f5311d84ed89173962073dbc2e3f2cd93b46dda07f0551e7dfdd92ae2fa4c2e22549c0d8fb5cde785b7fdb44f9702a250fb60bd6ddee28abe6fb0621144cac84b5c925d6c92e515b15ee046120a212b85b
#TRUST-RSA-SHA256 68cdd43fdbc5ba4f36d2e0896c7cb5d642da61d4b2bfaacf34cf85857fec6d210b2d7ff45f488c5cb6f6e3cb0a318c5c88cea20b47f6bdb7ad509e7c20f78ac0ee2892533f373757bfaf2bc1c7200dd268a43a7d0625d38831e2455f5eb574219f9ba7340c00a4f19e688bce79e9666580b16c2563a4769b0d3b73b199a611cd31071724b4a9b8e88f6185a047283a215c93dc8c0cce4c2a781a43a8c6dc52f166f28caf7c9374ed6227eea563b9e1edf2c4acac03bfacfa7fde7d571f4179a84ee96d2ee706263bc6ce1018b241cc3f33006d3c0272501232924c36016b35e13e8f64bbff0220e85c8aacfdddedcebfbf2c6cdec829a3a52288ee8b784c713aeee549c4d64e5283ecbafc268c3fb0171b064e71227b727fef60028108022e58c5919b6fe6a8957c9a23b22fc6c6b2511b07ef77224bba79f24f19dcae964367746137f387b5f71cb4f4e015eb58263db241a2e632be78a0797303370e16c4a5bf8d0468c42e382169bd0f050c79acb9c3bd06e19de551ef646fd0cfc038a69c5d65a33725037ed6a7a44ec7e6887c3ee6c574273a1b74e2fbba578584917021131c06aa75c5d7ca3e11dba221021741a2dfb430aec8356d97336716766d8b27a1bb5300cdf9da6404ad0c1ea5434c7c30071082b6226d30f9417c6913546bd6e4b4086b2c23fb690314b99c56ec24154b37f3b0402188af33899925477916a5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124331);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2018-0248");
  script_bugtraq_id(108009);
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb35683");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd64417");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve58704");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve68131");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve82306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve88013");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve90361");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve90365");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91536");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91601");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve92619");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve93039");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve93215");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve93547");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94052");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94683");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94821");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94942");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95046");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95104");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95848");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95866");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95898");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95987");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve96534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve96615");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve96858");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve96879");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve97734");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve97771");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve98357");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve98393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve98434");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve99020");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve99072");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve99212");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve99744");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf01690");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf02412");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf06525");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf08015");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15789");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf16237");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf16322");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf16358");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf20684");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf27133");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf27342");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf42722");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47085");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47430");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47934");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf54469");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf57639");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf58849");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf59210");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf59796");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf59799");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-gui");
  script_xref(name:"IAVA", value:"2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Software GUI Configuration Denial of Service Vulnerabilities");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following vulnerability

  - Multiple vulnerabilities in the administrative GUI
    configuration feature of Cisco Wireless LAN Controller
    (WLC) Software could allow an authenticated, remote
    attacker to cause the device to reload unexpectedly
    during device configuration when the administrator is
    using this GUI, causing a denial of service (DoS)
    condition on an affected device. The attacker would need
    to have valid administrator credentials on the
    device.These vulnerabilities are due to incomplete input
    validation for unexpected configuration options that the
    attacker could submit while accessing the GUI
    configuration menus. An attacker could exploit these
    vulnerabilities by authenticating to the device and
    submitting crafted user input when using the
    administrative GUI configuration feature. A successful
    exploit could allow the attacker to cause the device to
    reload, resulting in a DoS condition.These
    vulnerabilities have a Security Impact Rating (SIR) of
    High because they could be exploited when the software
    fix for the Cisco Wireless LAN Controller Cross-Site
    Request Forgery Vulnerability [https://tools.cisco.com/
    security/center/content/CiscoSecurityAdvisory/cisco-
    sa-20190417-wlc-csrf] is not in place. In that case, an
    unauthenticated attacker who first exploits the cross-
    site request forgery vulnerability could perform
    arbitrary commands with the privileges of the
    administrator user by exploiting the vulnerabilities
    described in this advisory. (CVE-2018-0248)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-gui
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?240d670d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf16322");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvf16322");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0248");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.3.150.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.111.0' }
];

var reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 
  'CSCvb35683 and ' +
  'CSCvd64417 and ' +
  'CSCve58704 and ' +
  'CSCve68131 and ' +
  'CSCve82306 and ' +
  'CSCve88013 and ' +
  'CSCve90361 and ' +
  'CSCve90365 and ' +
  'CSCve91536 and ' +
  'CSCve91601 and ' +
  'CSCve92619 and ' +
  'CSCve93039 and ' +
  'CSCve93215 and ' +
  'CSCve93547 and ' +
  'CSCve94030 and ' +
  'CSCve94052 and ' +
  'CSCve94683 and ' +
  'CSCve94821 and ' +
  'CSCve94942 and ' +
  'CSCve95046 and ' +
  'CSCve95104 and ' +
  'CSCve95848 and ' +
  'CSCve95866 and ' +
  'CSCve95898 and ' +
  'CSCve95987 and ' +
  'CSCve96534 and ' +
  'CSCve96615 and ' +
  'CSCve96858 and ' +
  'CSCve96879 and ' +
  'CSCve97734 and ' +
  'CSCve97771 and ' +
  'CSCve98357 and ' +
  'CSCve98393 and ' +
  'CSCve98434 and ' +
  'CSCve99020 and ' +
  'CSCve99072 and ' +
  'CSCve99212 and ' +
  'CSCve99744 and ' +
  'CSCvf01690 and ' +
  'CSCvf02412 and ' +
  'CSCvf06525 and ' +
  'CSCvf08015 and ' +
  'CSCvf15789 and ' +
  'CSCvf16237 and ' +
  'CSCvf16322 and ' +
  'CSCvf16358 and ' +
  'CSCvf20684 and ' +
  'CSCvf27133 and ' +
  'CSCvf27342 and ' +
  'CSCvf42722 and ' +
  'CSCvf47085 and ' +
  'CSCvf47220 and ' +
  'CSCvf47430 and ' +
  'CSCvf47934 and ' +
  'CSCvf54469 and ' +
  'CSCvf57639 and ' +
  'CSCvf58849 and ' +
  'CSCvf59210 and ' +
  'CSCvf59796 and ' +
  'CSCvf59799'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
