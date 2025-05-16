#TRUSTED 1a3909685a067f3703dfb1df54434f37e6cd6fc41e447d8051e16b8bf455ca6ae8091f94d6b091504d356dff4f6060f71a082ae5cc13ca0ea212cc890e7c7959103d0b70bb71b63dbd5c23d4b4a453677884c8a6b90da0aff3bbbe377f29137a2e49e864c9215ec8f13692ecc04a977720f27f7a121c5ff6de6f2e53a656959750821d9fcbe344b91dd9896e6f56e360a8d28f1fe42723d219e31bf8e88e8aea7047f218d1a24535ce05096d4644039354c55c660f62b9fa6ee51e807fd87879fc2e1f2cef81259682ab4afb94c43968f20e1bcd1c9f28713ed5be76babd54700fe3187addaa05a2c671911734d491d678fc3abc91d0dc9f1ae75b766f12b292b29ee87fe7bf9b52df141b1c337d22463040b69eb5514b40ffaeb9eee38e75e3391ed5cc9cfe675291b764ea239ee588409ad92dfb8555ef6ea2f5a527f31601713caa04126aca8dbc0640ee2d7a836d48c730a841d2ecba228d1daa4c63634e493cbdaca6a1baa65870e56465581b205daafc25c28deea8289aa836158fdb85fb2a7933c1245c148b50e88a5f63672793eed9f7501cd69a3e239527c5365dec6dd47d29df982acd9c7a73f62d8eb2e68948c28a589a001911caffceaf7bdfeb2e1cfa3c614388c4969b60630b623bfe2cb94756c1d1d4312a09416fc2dd850619fd35f4ffce24264565168efa8182c774d201f7c0ce3383a44e562f7b0325ec
#TRUST-RSA-SHA256 5bfc0cd98d3852a43948c89bee14ec6ebb7dbd08ea6af8f73f3d45b41c29c6bea2d80d009805c6fce88c26057fb389aff3153c2f383d3da8584d46f6e46bdaa5078ed105e1a88d21918b07286cad93e7703a75f5c0036da89cb1b947aa3153e1a3285fd7b450683f012792bbf236a2506a54a89efac171352999e5fd46659e8d35cce407a97303cb607d7de60374273e05f3f446b9541aff9dea7e32b59532dc31bb2157c020e58472b2945399c4c76b0a91f320fd1e0246a478468f9f4ab176d2263488b3bac361a3aa60da96e9010a5ca3ccbaa8bff1b1fa83617d09ba211a05cc7396b3dede3deb2f179d45705ab65855bec88b69ecf946e7462457205c2aeb194ca94be9a37981aa7bb21dcd826acbb06be0b73483d80735c1c5dfda282ba9fd802cbb0d503358f29b7fbb08c82ae614aea1e4e4da25a47e1c5abf5daa4afa2eef372b2e7655a8a9171f002c5ac4445c8b4465317235f4a2bac1ca7aa409050c038ef3f5a44aeacc822962d60368f21a9dd22a2ac417af157f03668d4ca7cade76bdbf33a1439867ea71b736dc75b9e64889f9d907edd8d0256d389a5fc97d152e5825b45180df0c7b337e431f9f25c17c18fb00fc39c9a70b50f2af12212911f2400203a6b70299401d1e66a796c1cfa8556bb9fd502ae48bff4cb1d96be0eac525f60f978857e7e598061abd5d716745a57fdbde880b59e8036e6e2769
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154197);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/27");

  script_cve_id("CVE-2021-1621");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw43399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-quewedge-69BsHUBW");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software Interface Queue Wedge DoS (cisco-sa-quewedge-69BsHUBW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability in the layer 2 punt code
that allows an unauthenticated, adjacent attacker to cause a queue wedge on an interface that receives specific Layer 2
frames, resulting in a denial of service (DoS) condition. This vulnerability is due to improper handling of certain
Layer 2 frames. An attacker could exploit this vulnerability by sending specific Layer 2 frames on the segment the
router is connected to. A successful exploit could allow the attacker to cause a queue wedge on the interface,
resulting in a DoS condition. Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-quewedge-69BsHUBW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f60b0fe");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw43399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw43399");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ((model !~ "IS?R" || model !~ "1[0-9]+|4[0-9]+") &&
    ('ASR' >!< model || model !~ "1[0-9]+") &&
    ('CSR' >!< model || model !~ "1[0-9]+V") &&
    ("ISRV" >!< model)
    )
  audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
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
  '16.12.2a',
  '16.12.3',
  '16.12.2s',
  '16.12.1t',
  '16.12.2t',
  '16.12.4',
  '16.12.3s',
  '16.12.1z',
  '16.12.3a',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.2',
  '17.1.1t',
  '17.1.3',
  '17.2.1',
  '17.2.1r',
  '17.2.1a',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.2',
  '17.3.1a',
  '17.3.2a'
);

var workarounds, workaround_params, disable_caveat, cmds;
# < 17.3.1 only vuln if it does not support autonomic networking - no 17.3 vuln version needs a workaround check
if (product_info['version'] !~ "17\.3([^0-9]|$)")
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['no_autonomic_networking'];
  disable_caveat = FALSE;
  cmds = make_list('show running-config all');
}
else
  disable_caveat = TRUE;

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvw43399',
  'version'  , product_info['version'],
  'disable_caveat', disable_caveat
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
