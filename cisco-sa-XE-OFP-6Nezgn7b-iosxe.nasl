#TRUSTED 604d004e69ef232886832bd2dae055223a3c6402fb923dcc64ff74c10e8ca30b0558b398b0446a3c0627c24f7c41f4dc9d8b6350d6877606d87f42698136f526db806bc432366748bd1021c4b5b81fc47a8f288553fdfc98ef243a2c4ec6ec719820cd89d329826d7284649c4ad965e9d3842ea74c5fadd4845d7a7aff1bb1e08099b051ac14ee1c3ac73ef0f10d8a17f582b4d3ade867dcfbcfea58b92f4f4acf47a7fd21d08b03f5a137de15dfab18a17963083f45626915d0af94bbbaa1f7077650fa2ebc2c6c40ac9bb1638635aca501512e5e42545de833cf929b040239c3770d97ed4fed0c9e7d98438ae7474e0ecb754a514865efa7693f30b8a3932bc76fd41a5f2661f7ae80f482a38ed064a35daecba23918a48e30688f87c63a0c0113de8e70d16d5740b8a2533dd4cf421323183719f663e707746f1df75c41eecb0181d3904ca3de40affa767d85c2a5caed0a9e7e9ce871e0a60f939a2033ac09e7f887a996a7926336271aabb7beae3929865244864af620a1fa20dd5712bbc01bd72c7ce0c07d76dca554582f6ff0f2b53b3b6e32f3c5ba152db6501c2220736b7529f0c4ef0e99e483002b447b308d09baa6ad2ffab8552ddc616a4e02d256a45172deaf5a776f638410da75ea1d744d571b2ef52072bbca9f8ff4450a20d108e6b297006c25035e5496a517a1b29f6735f6ede25472801f194e1b11b644
#TRUST-RSA-SHA256 5300a9756635d91e1778a09f7c2d0ac5ea12dc16ff32a75427b129849fc59bb4adac4f02b697e84f65a5e32b10a5f2e66f573dd1b8b3a68583e8c2ad17566f49903e3ff6a0f8965910533e57a644de2d9fa835458983ba8275229ed05097cd14f869f7e59f08b94283710fd3dff9524bacc108df8c17144efc4a52be372d5ef9874238be9f6e019bd54866ae0bff18f95c681b389c36ab537f167bca58ad9f3465bfc3795998d1f953e57d676014f7e6b7f1b40fc47b2faebbb452a8600b432f2bada39f6fb5eb740eb97adcb532baff115d2972508966950b60637f4916fcb9627604aa3610b3647066c0699cef2136613a4496ae3c21c2253285c27a2515ebebc23696be374c72652b3a245098dfa7453c830005a845ce0f17802e000d032476883f4e3e0feaa891098b25fe7acc98643d501a31139b4924bde73163fc694a94921f30e74684736fd6ab59d658cdcc397071932eb07a5bdd0c8117caf13475e38e0abceec639be02a252b1c704f1f5a6124bd7433490a157d55d8fbfea591b59e27baaf6ce8b5fa1fa74741dbd38eb18034fb7e187a1629a362f327cc6f18421e78079c870cbc85470e2a46f5efb95ea73ff69cdca2712fce27b5ddef0b68bfafb24f4250acbb30d65b5b7bddf49f60d65a848b7f29b56443178ea7e709a4847906cd6af22eb251382059d22eb7d543eecfdb5e8e8723ff4e003b390993e7d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148096);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1390");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu78930");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-OFP-6Nezgn7b");

  script_name(english:"Cisco IOS XE Software Local Privilege Escalation (cisco-sa-XE-OFP-6Nezgn7b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-OFP-6Nezgn7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8408b84c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu78930");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu78930");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(123);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '3200')) &&
    (model !~ 'cat' || (model !~ '3300')) &&
    (model !~ 'cat' || (model !~ '3400')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu78930',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
