#TRUSTED 5a97ecd25f4930b6a6a907520566cd7f850f84ce8061454c64e20199ef29b9d8e2070c2ac5145b6ae32e86de23e1c73572ecf01296a3ec264b22f8fe3e039c1822986fd1c1ae73fdf0cd3907ad89d0dff65a405eafb8e79df079a320777c085b4947eb32f848c8b2bbe52971b6d58c3c5c600b43b0ee226d520e431105733606a4db4bbfd1decdea07ac6217a6b8bf387d244d504b5635958111b2267a49e8e25b56646c3fea2921074f361fccc39343f2e358d65230d62c47ad44a69d00a170822fc5290e94cebd7b1effb409b7765470cbb02a459942d5c20a236eb4b3cde9fd186c8e8691a0861e084a4395be90d541d01d6bdedd79acb3edf2ba818c39a349a9e87b0cfa76f94c7763aebbb9a100e202a1e606435aa5f30e1c73f051379ba1e2bfd357b5e2844a2af30e24c2ac722a04ea7d0ae7edf72751c7a6e4eebf4ee5e2ae5ae8285ffba0dcd76bcbe5df0fed30522d0af646ef94a48e1746eab8dd44c47eb676fc1634555ebbc3e7fa51ba771a1d6d7a06fd8000de7f6b9fc2902f43ea891949c5ea50eb7291e13e6e49f29f8862768da8bd89d0585f4fbb55ba7b667017d324e7c638b07bc6307cfbc087525f24226ea10026a6fc23b6fca34fb5b75d594f03c69cc1e7892d4c989c25583501552c836d59a8977be12025983f50829776fa805cf350f0ea91195c2a2d02c8abad033fc0a485919c045aa1ccd006
#TRUST-RSA-SHA256 7b1907d96a930a864dc230a70723ece92827f29a4f351ecb6b20a56ef8511133c5641ac45854a7a6d86af9fb5b6703e231959dd59797a7a7d75a3ba7e7dbf800bc687c799a909fd423d638de77cfdbdf1cdf20092b1a984e60f692b62ecff6b8c5914ad3e1effd5575e69214f68a734828b19a4a17a041b968b6b000b1f6d524d8a495ee773be25ade5a6a654c21055206f90f18ed956b82fd288d20a9504ffae3fae25d5b1137df92d16bd8ab584343bb838954b9a15c78e4d223c26777ac72236aca430f6be57bd061fe5b0259633fa8c172b903d19921c3847fa3146c7bd3abf27a17c08c3600a54b085cec3a3aa5bb184a575b53cc47b87279d968408b955c247f8cff002d738838616fa7a87a4259efd3182b6bab415ba3367ff17330e30bfa791677ad70c9f0653847327a18720f6756d76c52a161d7b67c049a407ed942a8d8b3ab3ab1d8263e399834d1f7f25d33fa043f680c14184a52ec4a2a91187f82e73582cfcdd1ffc12e1c87eee0eb6505088be55a9378d11d529a8f1ad8c298f74166a5923de32ec622078d41c8f2d908f0f8998e25be634e9646e39b3c1a2871afe73f61101cfd4155c3dc2a5a449ecebc479d420ab66db8155d72b941ded0c000b4bed0491b0adfc78a0ffcceb3e146cfd1bbd81b1540e0f667415ef1675fdaf251928c78c052e0a59ba100a29ebe6d2d032530553a872ea6e8405ef42f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141115);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3503");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr50414");
  script_xref(name:"CISCO-SA", value:"cisco-sa-unauth-file-access-eBTWkKVW");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Guest Shell Unauthorized File System Access (cisco-sa-unauth-file-access-eBTWkKVW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an unauthorized file system access 
vulnerability in its guest shell component due to insufficient file system permissions. An authenticated, local 
attacker could exploit this, to view or modify restricted information or configurations that are normally not 
accessible to system administrators.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-unauth-file-access-eBTWkKVW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?366d7b81");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr50414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr50414");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

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
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
version_list = make_list('16.12.1y', '16.12.3', '16.12.3a');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['iosxe_guest_shell_enabled'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr50414',
  'cmds'     , make_list('show app-hosting detail appid guestshell')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
