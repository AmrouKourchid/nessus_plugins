#TRUSTED 3b1c1c77f39b533d43c7abb2fe9bfd3a9a913c9b280acf68127eaa45208bf756fc9e8d59d9a1a50e15483ea1bc14f4ffe7aecd75e78203ebc9c40642aaaff51bbadeec3d9b9a8290aa7aac8e0b61fb52953d497e4feaf4b0a990bfb74ab23a4c9c7b71b289f0a26edeb64b523d9d299af28faddd4289b35a67094253b4dce9e7cba8c89a0fd02a743d3003e66d2f267fc13b2fed1d9b69d8f19a1ef2171a63f3c55d02fd6df99817f025afab86fd980fb3c0f005c60bcca21f8096a263a87089ae5ae6f1ef637bf7cdfe04670df32fc1f06affd46477b117fbab7d689f2c431a70deaf08300f2f069ece163f27f6c51487022105e9edb995da813d0024909727d6dea99d429f2c363921df74ff30ceed8e32562e925acf56d3addf8ee5720b0b22b8a763e81e1c18d2a01a0be4b44d9a2f75c371b873e17837277482cad9fd0e632b2b8056b54550b4b62e490452bae64eb65b7a5d0d9357d8b1635e7da47870ae1734515f8b2ddba7645969f75c9f027fa781bc5a292104cfed214c04a8d22936bc1a645929f30cc7864d88ee300d63daadc3a57633d934cd11a24c1444acd81105e89458377e8ad31a44d58f106bae32123ec2b5418a9363682d5599db31182f7b5d5cd0cd1ace081a05ffe79c63237deaf25e64e13a2acd714e10af888088a26bf670f6d188f3f1c854f835bcc3b93d390eca1878dcba4d76e51585079853
#TRUST-RSA-SHA256 3423886095d5ce54c58b2a9b3679ca83e5212cdfee19641985460c9dece0e350142ebe48a804c2365f97f74a7d7011e6ad785c16af5e2ad3862784ab930c63eb05718accd2da4af75f1dea031319f00baa53fba5a8519fa4fd09b655d0d1ec3de49c25add3efbe1733312b0526123be48738bd747e0ef961088b781714f09cff22693f14eb1b7d8b4b4053a396ec9e7cc2a44e213ce88de6a9495d1c976fc7e577d77a5b7410875a654fde6dad4f698a428ad3fb3c59b2feeff2ba0fd1653cfe10a7eee9bbd9511d28323233534cfe82d1d530505e2bf67e9d2a04a46fbc796b5527382425791195bc9e628f3c2c0c4b6df26a1d5a7742ff4c3c7e8b6212a433f6ebb3535ea6787cd562139d4bf18a45227640bab1d28b8af835fa91467bc430ef765adc480d704a2ed60041e77ad2482aee9a64b7a0d5c9bc5c3bf798fb6fe3f1c6defeeee32f0f31df7b0a41d2b13cd5c72dde7a700402944a4d76fe3ba0824ca2b1de50753b4eae70db85e14c285e4e95fe39eb511665a5a2c2ab1c35063aaa85a3481c383168607e8865b8da424c2c6657bfa7180c552e425ac8cf305ef86349ac0d0635c8e34c6ad727018344cd15fdc74bc8b5d99208c6f283d3581b9c145e0bd8dd1eff1025bc42ed0081bd5e902a15276c6ce354cda0dc4ae69c767ab84e1dd86102538fd1eb9a52925fcb8243c89a20d35981452973afb5205a64e9
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183298);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/18");

  script_cve_id("CVE-2023-20231");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe12578");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-cmdij-FzZAeXAy");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-webui-cmdij-FzZAeXAy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the web UI of Cisco IOS XE Software could allow an authenticated, remote attacker to
    perform an injection attack against an affected device. This vulnerability is due to insufficient input
    validation. An attacker could exploit this vulnerability by sending crafted input to the web UI. A
    successful exploit could allow the attacker to execute arbitrary Cisco IOS XE Software CLI commands with
    level 15 privileges. Note: This vulnerability is exploitable only if the attacker obtains the credentials
    for a Lobby Ambassador account. This account is not configured by default. (CVE-2023-20231)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdij-FzZAeXAy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1304a2d");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74916
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3520ae2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe12578");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe12578");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9100X|9300|9400|9500|9800|9800-CL")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '16.12.9',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.5',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.2',
  '17.9.2a',
  '17.9.2b',
  '17.10.1',
  '17.10.1a',
  '17.10.1b'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['HTTP_Server_iosxe'],
  WORKAROUND_CONFIG['lobby_ambassador_enabled'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe12578',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
