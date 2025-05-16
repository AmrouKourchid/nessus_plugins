#TRUSTED 837ead9f66feeb194312fdfe11cb8cdf21dccbe2687747d37aa4bc0a31a3d488434a374ca5eed7d66b21b403bba10b766ffe5580ef315556136424aba6bac47e7a225511c34954a1da3c4fab5304ea5c2b6c88e7755ff3e6c856afe983fac47c383cd16fb09f8001138ec58dc66babba4199b66ba7d9063ad72dead4fa178cc59520db04a39f280b175b77161125756f21666edfd21c48ce4f1a38d0fc3ee25320ca8f8ebdb6bd5c859fb2cd3d7300aa3eb7013013a9eb2813988ab7f535a75b9f29782504a0f642ece5cbfd74f95376831f1f6b97c29c4e2c843f586c4aa91faa56fb53ee8e1b6d450ba4bf5587ea27a992380bfe206d11a45ecdd77e60a6024d11c9a37cf2b8a0f750f94828029f0b4ca12c0c5451d13a6c71b5ef05c216bf01457f65d3ac172d8a962b3dfb28611a0b88e5e710fad3bfdbe20946b13c62579f755fff60dc2d23082eff5b55c8fa7847070b3eb98a9aae0942143ec02211058115505bf251208d09cf00ab5486dab7ecfeb0a3907e563921c58ea4c29b5c3f16ea2e943ac00785945a293e50ea080a8533b1d43551ea5b15535c7f8cb18bad0a6d5c558f6f60eb10bec3b224245cd6324774fa21ebf154cd7de6aef16d800d9cb805ce083351934a309af80cb994dcd604b94a13f2a8d66ef16a60c77c5ecad2213a37b22508e85a3df02840ea20d36e431db54e66969e30441a804e45708d
#TRUST-RSA-SHA256 b250cac2c5edb14ba0f4ffb23bd7790b5e0d89c0caf2b3d0455b2caf0e0ec9b08bcd6ec1c6687eb35aa7118a42aea1a7c11698bf6def1f96f9565bcb530d9db69a45e164fbefa95bf0889b28cee385dc59f1370c628202ab96354449da2ab7dade6c247e1061fcae8cf28df91cdb7339baaac6a6cf98c93e2b98d733b84cb41e78383a46095aa23c556baa70f1095a4de71513dbdbb5313d960c0adb19003744b32e7ac2537fc1ec2a7f2e94fda7a07bc644e0cb57850229508ac7b97d720d9b5684066a54e066d6faab63edb5d78eb5b332b74424c385323748477c0e0f5886a143379d4b8a2c636893bbe3bf919ef34a6d14b1528212d3e8ee4cf2a9d207f265bb6f61e8e32b3cccade15ea1deb8d510c7100e690d9f7a1541722dc3ae6db7c77bf7ad35b60e608c99d12e2e1b8ec4924e99b321940ca1e92c5706f7a3c5d04daf3910b3825d78de1506028ed8893fb66801d4e36b5a7a72f94a68c7bca10ec49d8807b9539fbb31964b6248eccec9cad620db12380c0234356774dd33f7a62492ecfe04b517a5f5e2d2909bc239beb676a50f4b03acb1b4268d2c2b0e7cefb44cd967814177e885f3ae50c25a9d3c371b123f4d36338c34e09f1c3e5264771aa3bbf0bc2ed30847c6a615ac34e1ebdb06f0cd5dff5091c52c0fbca1e4f39445d595c8af3d74483fde7b7592a6d581b0b9053bc26f108cf164784e067a75bb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214884);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20390");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj39201");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-xml-tcpdos-ZEXvrU2S");
  script_xref(name:"IAVA", value:"2024-A-0573-S");

  script_name(english:"Cisco IOS XR Software Dedicated XML Agent TCP DoS (cisco-sa-iosxr-xml-tcpdos-ZEXvrU2S)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the Dedicated XML Agent feature of Cisco IOS XR Software could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS) on XML TCP listen port 38751. This
    vulnerability is due to a lack of proper error validation of ingress XML packets. An attacker could
    exploit this vulnerability by sending a sustained, crafted stream of XML traffic to a targeted device. A
    successful exploit could allow the attacker to cause XML TCP port 38751 to become unreachable while the
    attack traffic persists. (CVE-2024-20390)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-xml-tcpdos-ZEXvrU2S
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5531c048");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75416
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a636b5a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj39201");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj39201");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(940);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
var smus;

if ('IOSXRWBD' >< model || 'NCS5500' >< model)
{
    smus['7.11.2'] = 'CSCwj39201';
}

var vuln_ranges = [
  {'min_ver': '0', 'fix_ver': '7.12'},
  {'min_ver': '24.1', 'fix_ver': '24.1.2'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['xml_agent_no_tty'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'fix'     , '24.1.2',
  'bug_id'  , 'CSCwj39201'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
