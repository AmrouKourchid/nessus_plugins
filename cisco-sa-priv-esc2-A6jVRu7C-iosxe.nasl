#TRUSTED 7e64b10efc49eabea60975fb2893abce00a3d59cdf3903380ed955ba841a3dd4196f42709cd84b7d2a432f569f50d8e3c9aca5b690ff6c5fed4e805c59be28a3c7ec7289122606ceea7467713608a25ae6f43d32e138634d52d3f0a8f5a142ac87e3ad89825128537e4c24790315450ae239b6ea90f844c6d27057dddffbf50aae44010dd203327d282cd5782fa7cf1d63f7a5ddf4a7ecdcbe75c80955105e081ff8157882a32d92b64a6110e55222bf95659e8b80ac7daaa65127d113b3b3b4059b92e76b28db0435d59ae527f518d0e5d3de116e6ba64e5ff388e9410ea7b029637145909e88884eddf4d1b4ce7f973081094c9fde6c42c76272a1cfb485ce100132e8bb73099d42cff566dd38308419c1172f1354fc947485f9132fb29cd3b579dd39e5333a60e408653694b9b184bbacbaeadd6b42c6fa01c5043d9d034b231788fc05e6f364d09657503a645684c7126e8b18e3212d50084029f8ff13d2f959a973f21111c9ec82c01d188c06777296ffa30e5f6f6321a1d640ee53528ce923e6cc67b2a0f6381e35c756a39e4003e6b419b08b40dda40f1319257f37f86b984c49e304f0e2699c55a3d9f9c31a493041c40e76eb793ca5ef5fe994657ed7cc92f0a8d5c84153e046607b10aa2f2d2085e883b36e4883dad73840ab5c589dedc74327c4adc9c93a8fce0c9641ba20d52395cd34d0847eaf3259af626921
#TRUST-RSA-SHA256 5eab7cea6543e070b6af8f2a1a9546b47422d8aa77de0480ad1c985a00e524ceb172a8fd7fb03f7358ee215f1cc8f169b4d085bf367133cd455e6584978b839a2d29f4799ef948997b7e896b703b7182750d2408f30e8f3d9788fa4303543d9cab6e31decf56392dd14ac6f25f582c250e5f45bb2d7e1aac468a5a0f51cb3527849389ad1de67023023164d03baa8b59588d7af6074dedc89573b27a3ca4e91904755ce5acb9f9ab6748ab9bf489424446008a1038a323c834b25ccd1d912be5806d7398364ea3d8ad0c91e98b17bac4505d844bd31070054c3d86c7aba9f00f09db507d3709f8a8df38f2962a27e6730f6c312174715c5adde40194cdd804f220ff20c9ddc9a1df538beb73b648034d4003765e746a826062f838c135b908f82e1276887e5bfcca91ed6dcf30fa8a323f7016b4cd1de4e36bd18fd36bb4a1176eeefbef31173aa54c137536d4eed99a049ca9702c914423104043861118cc3af4931c4dbc6b97c672629df29acdfc09d09aa0a1060e6c02fd191ddfca4d0764969b05ab85da5f86a19199e35ae2bb5d6fc667b9c79d917cabe6063636240bcb41c2ce6e8d3dfd7cf7774da54ddfb7d9977fd8bdc8321e10563aa2b0773d59c0ffb358be93a7149163c54fdde0a11cd889e4da788179bcaecebe90d14eda3ed10469178bf2a0e2f1ab7e6d87059ad1bcb4633329001acd5352b8d12133239cd5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137361);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3214");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq24021");
  script_xref(name:"CISCO-SA", value:"cisco-sa-priv-esc2-A6jVRu7C");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Privilege Escalation (cisco-sa-priv-esc2-A6jVRu7C)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by Privilege Escalation vulnerability. An
authenticated, local attacker to escalate their privileges to a user with root-level privileges due to insufficient
validation of user-supplied content. This vulnerability could allow an attacker to load malicious software onto an
affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-priv-esc2-A6jVRu7C
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fab2941d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq24021");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq24021");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq24021',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
