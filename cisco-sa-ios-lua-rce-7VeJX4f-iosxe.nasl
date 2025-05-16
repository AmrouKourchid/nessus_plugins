#TRUSTED 5cc0166f9883f66da61d16f27db9b1dbc20b670180f500c0c456c368f14412777d11dd8bbcef3acce634564312ae64524001dfdb87f58cfb4d6b861c8df54a5599cdf9d644dd3e97f9a0f0af5bdb23089b7d1ce3841144595dc3f30a1099e64c0cd03520bbd864fefdfba15127ca9a9b717c83d7c6d2153bb6a55fa961cd98946cdff5ab684f48714df4be78e67cd882a9ba27cc456daad00d2003e16a84d5a4700e79c5693d977e5687c558e049af677bd26b1e6c830117ae634bebae0241c9e0770b7cc7b4ba6df24533377f0796b2ce99bb5ad8b50707ff0dac387377d2f3bf8f6c5068c8bb129375d45ddca2460c357fb58df7ff63eb47365532f1c66aebde5d701d8eeaa741a07549240f112172ab280cb494668cbe9cae031b83f62421bcac964bee3b64087b970c8a596c061e098d87a4cf248be0bc209662f1810fa513581cf3a548f609cf946967068dc9c0357dec518d59855904e96538083a5fd1a429c66ff5ae271e80c15f7aab37be33d4c5bbfb492abd27382d769a32ea7a8e993ae666ae426cd7c17334131cf5ac07d8e9e4f9ec4dbbe238b6be122e751678964eba19679cc8c022d014f230c67a7cdbce817502a8091facbccdbd530a3f9ca29a5c0d461a9aaddfffef18c3f16184f0018caa46f96f1600990078fb5d1c72926e8338720bb9daf62476473f709f64c3542f320c6327a7dd610ab66cbdaf92
#TRUST-RSA-SHA256 607c41d3ccbe08cde8934fd079b2456dd8934428a469de5b635fa52a1c9322f0e44e82a89cd65eee425c1051742c30c3903641730a118ba397fef85033fcd662b4372844b4266127bf7367b8bd70bc7dd902bf39fa979ebd1f45fa153b0129ae26128841adf3192e79edc9c3ff7bfb77a335a02cd93b62b25e834dcc3202764feb101c67080aeb02520a7dd7f6d3715deee993fe5a1dc9ea2d92dd9dc53c88f77f64c969605763ebfddf723d623f4cca951530f17c4dfcb092fe1a779abf4d5ea9917147bfc2a474b52872120dc7532670017b13ebfabd5d75f76da8d76308b90659e083b98e8700c76c58999e0f640e0bd135dbed0d4ef362e98f8ef7d8beba09047b96a4f2bf4388518181f1924c335e10b860541470fb1186b7fb542c0157aa81db365f017e5baddcc2f07f6498036b0d3c33ccd19e5a645b6ea588febd8d076eb7402a4b7a7ec8b69444696f39b97de252e63d8736413d3870760f293256bfaf28473e2df2260a3d5ff734a068d55458b6c9a3f876a9403c4e9a147930c3bd42945517996f9b9ca2585a81650b307f760c7181bb9ae3dbf4c14fbb471cb29957562fef64bb855bde7e560cd31b236b6b98d6f7285fc11ee89eeb205b0807198c7bb1ce7191c6ee3c0a5aef54786695a06c1bf4ed37ad784d2aff33e396c580a8935cea67d907ec44f651dd4ab03285a41f9047357e1bf80efe57d289d705
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141113);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3423");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs58804");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-lua-rce-7VeJX4f");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution (cisco-sa-ios-lua-rce-7VeJX4f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an arbitrary code execution vulnerability
in its Lua interpreter due to insufficient permission checks on Lua function calls. An authenticated, local attacker 
can exploit this to bypass authentication and execute arbitrary commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-lua-rce-7VeJX4f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d0a7b31");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs58804");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs58804");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];

if (model !~ "ISR" && model !~ "ASR1" && model !~ "CSR1")
  audit(AUDIT_DEVICE_NOT_VULN, model);

version_list = make_list(
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1s',
  '16.9.3',
  '16.9.2s',
  '16.9.4',
  '16.9.3s',
  '16.9.5',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1e',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.2',
  '16.12.3',
  '16.12.2s',
  '16.12.1t',
  '16.12.2t',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.2.1t',
  '17.2.1v'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs58804',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
