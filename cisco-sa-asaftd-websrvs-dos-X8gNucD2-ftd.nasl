#TRUSTED 25dea27f59190e817b2289c4f0dd5f7c6ea91f2970414582340f76a8076f2fb5a12445e912d9b2f3f3b0335070d6f50dcca7ee58bde6e7bd1c595154adfae504e75c74be75aecec87b9f1b96f4bcc0d9433df56f80cdc54a22c3a85ed13a10168840d7f30248f6eb390a06139f9933aa1452b11d5eaf438694d40671ddd22bf733c1e1513ba7497eca1a5cb8877696291877165cdadc5a9f06085d991f2329b720ddaf1461f010c04f9c0e2039ded47f7fe38cd851009de5ec58612193d964d1ba078a0746f5a7c60f93a45445db92c83d769df2028928ffedbd3c0a0d2031abc5706665e1b20046dc740287d82855ce1d570acedbf7cfe5bd72356d5009c8311af4595a91f2a32d966fbcc53cc80f508966c055747da508dcc4f0ea86ef0d7b7ad39caf128645e0874cf575541f2be35068dc7e5ce5e9fd6e4b27e66e14753c7e721695b23cc9efca4c19edb4678b51cbc1365ad89e462d500fa04fd25bcc9a93df5971a70cc8b3b4f18b393fb4ffcbeed016474406de1da110741fe3bdef0b36a2a6f506f2d077ed1f74e6afc7c6ba1580bda467a2a8c2f26bbd342185a34d7274cbe42ceacb5c4bb93123bd136124549d4ce58a95cb69c761b4e76be6def14737e59395e0146f5fa64b11572a851c9c46b2edfe1605c4eb3e901e0edff35a4852d998e1eeaa0178fad9a4e5b891501ba1204617fea3cb49d12906c2d98ba5
#TRUST-RSA-SHA256 6cf4623f49670bb3ab936e3c7792e2b869fb060ccf9aa11a9cf9c230ee3c4934984b3ef2253ace5d947b92f4649308425c7fb92b987dbb55d7b55865ef1df954a0346a91d650950350d415aeeb37e319d9d94be5acc94d21217f8a5aa68e0a2b064303b090c91cab5c63708d73f659b7b2cea69a740a50f3c08ad861f0e27afec3f808192198d8c31106d36b77ff52f6254744bfa9da0bbdc3a20dd9e220d6b0f79e66e9cba2cf4f160c6b21c7ca3956da3e9bbdbae04eb96b9ec92d1c6aae796a9227af051ec4da4349614e63ee56d7a97f4a042184ed6d08074924fa204df2c775a3b7b8bbf3054dfd1a699b0a83f8a6430d243f1f803b4d36d9e67de10b73ae329147304b676ee45fa5b2beaf597dc2f50b68ad0831a124f1dd07d78ac1b678b9509ac3a530b7650c9e72014d7546662e471245ea541121a14e68905c8ab87377d08b06d19ebfd600cbf3ea5e113d65a619e7b0ad79208c7a666487a788a090e805d04a9eac875969277626897998c1063e493188e3fbcfbe68fbc89f7faeb980b3ff282f4a7908ce5e61cb81683a9d18bb4d62cbcc14ad60de2eb6fcd101d7abad0a3626172ff59e2d36bd30eda2f5d8f5f8103db98ad0868494f092e9f7991293baf3ea0463ccf04e83fa7154dd661f3a3a9cdb01ab9aa9aab0c61237b1a54644a57f71938c4d15f75ea5524dee0722f8699d53d4c65f7236a80b32571d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193914);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-20353");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj10955");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-websrvs-dos-X8gNucD2");
  script_xref(name:"CEA-ID", value:"CEA-2024-0007");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/05/01");
  script_xref(name:"IAVA", value:"2024-A-0252-S");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services DoS Vulnerability (cisco-sa-asaftd-websrvs-dos-X8gNucD2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Firepower Threat Defense Software is affected by a denial of
service (DoS) vulnerability, due to incomplete error checking when parsing HTTP headers. An unauthenticated, remote
attacker can exploit this issue, via specially crafted HTTP request, to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-websrvs-dos-X8gNucD2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d89c58cf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj10955");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20353");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_versions = make_list(
  '6.2.3',
  '6.2.3.1',
  '6.2.3.2',
  '6.2.3.3',
  '6.2.3.4',
  '6.2.3.5',
  '6.2.3.6',
  '6.2.3.7',
  '6.2.3.8',
  '6.2.3.10',
  '6.2.3.11',
  '6.2.3.9',
  '6.2.3.12',
  '6.2.3.13',
  '6.2.3.14',
  '6.2.3.15',
  '6.2.3.16',
  '6.2.3.17',
  '6.2.3.18',
  '6.6.0',
  '6.6.0.1',
  '6.6.1',
  '6.6.3',
  '6.6.4',
  '6.6.5',
  '6.6.5.1',
  '6.6.5.2',
  '6.6.7',
  '6.6.7.1',
  '6.4.0',
  '6.4.0.1',
  '6.4.0.3',
  '6.4.0.2',
  '6.4.0.4',
  '6.4.0.5',
  '6.4.0.6',
  '6.4.0.7',
  '6.4.0.8',
  '6.4.0.9',
  '6.4.0.10',
  '6.4.0.11',
  '6.4.0.12',
  '6.4.0.13',
  '6.4.0.14',
  '6.4.0.15',
  '6.4.0.16',
  '6.4.0.17',
  '6.7.0',
  '6.7.0.1',
  '6.7.0.2',
  '6.7.0.3',
  '7.0.0',
  '7.0.0.1',
  '7.0.1',
  '7.0.1.1',
  '7.0.2',
  '7.0.2.1',
  '7.0.3',
  '7.0.4',
  '7.0.5',
  '7.0.6',
  '7.0.6.1',
  '7.1.0',
  '7.1.0.1',
  '7.1.0.2',
  '7.1.0.3',
  '7.2.0',
  '7.2.0.1',
  '7.2.1',
  '7.2.2',
  '7.2.3',
  '7.2.4',
  '7.2.4.1',
  '7.2.5',
  '7.2.5.1',
  '7.3.0',
  '7.3.1',
  '7.3.1.1',
  '7.4.0',
  '7.4.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['asa_ssl_service']];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwj10955'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
