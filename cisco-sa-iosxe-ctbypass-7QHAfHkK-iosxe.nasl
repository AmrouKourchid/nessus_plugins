#TRUSTED 5608314d4987efb10f9bb926e4898af3250b99145dab7c88c461def8bb939dc700dcd32731c487c183527101c96a216018c024dd474c469e9087c130223f408317944a3696c44f00cf30e52b673de6eda4c85c4a7b9bb943b52a12979c44221339b3760ad4c8e86213e1d12ca94215f180584e0ffefb31f3c11dff48afab55f9a951f88e27a7063ad05d822c818298b4e4c070c15fcd8ef2bd46609862dab8ccfe747029c2b8ae04543c3d1c954bc0b159c7e33c8b5b9bc1e708139cd2de1f71f215f2b4f75fdb6e08254092f20cf893d6b614f42e04c24cbc4aa9ffa038af6524c9019e936753b3d5f0d58f94dbeb8180db64438fc9d443feb1342eebc26c9b994d7912eacca42043751bf2d23f8364425d4c809293e4462c76f4631f1caae1382bc365549d3efedd60bdaa3d36be2d4f9da7b3aed1afc5ac665fef5855b3cd71ba445f4011d1883b56e5a7218018ff066d8e04c17d68e952fa0943042162109a4065acbe3fbe7cd6d9a979746221c3011efb4a39e36a029224294ec347a4874de30973d88124226073abdd985699343af4dcdc2fcd469cec6e69d54b4aca065f762cb329d8a93f89b44680097aa28a9f34283ab016e628787dc5f8b002f8b9c0afb47eb87ac267b40bee19299b1b43199f4ab45a15537e05693b8ce92cf33a1ceb7329b987eeaf9385bfc2ac2b17b437bfdc3021010d189ee42202bdf29af7
#TRUST-RSA-SHA256 4204f3292f038cb68ae9c5d9f78ca5434991548b97c49abee7473ad328ac924de9a196a64a613cf8ada6058999ce6a0c473f40013b429378fcaf5a38cde75704eaac143a7b59c2a6e7f6df798d960b6a4abd5ef831c1c4cdc0652977f1795b3dfd393cbf1144c8b2a84bd619f2f7bd71496d2953d703f700b41835008235d1712d95182bc689e3b2941d5f021f9646607a7fc316301aa4426fbec71f38e8f230d84c597fc37aca77db68a59f7ddcf09e95619594abfe72a41163040dd09000ef5d78dc870a7f39b8e15115dc1df38cdb6c655d3f37302dc16e09b9ac41b2dbecaf57bbedbbd37bcebab19f195a55687a3eba1378d43674f60243d8555527822b97fb7dee830cf04676e7116e2bca4463a131fe0242193eb9fd1db82a165be6c5c0993149481a8fc268dc704e09a7efea42c689c4b9a02cbd6e661c339c68444781e6f7d20bbe594507f41198f40fded15579dc0d83b5eb57ddec54aa4bd80172de0c6adf27af29c4ea024f490e64599361134603eab8e406ef13798d6f8d37f2e4079a7def9c431036c22cda2e18078e8483dfcac59bc4958399d1212136659bb2831dbbd2df0366fe9c83372d80afc4c6dd2c58f59c97e4142a2737dc94a46bd5d674248dd042b70c021b01e8781c32e21fa708dd90c30c3f683268943ec6110ff5e46358332c33acca0e76f6dd5e27f6ceb370456d244b230c505f40df7ce5
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142053);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2020-3404");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq91055");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-ctbypass-7QHAfHkK");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Consent Token Bypass (cisco-sa-iosxe-ctbypass-7QHAfHkK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a consent token bypass vulnerability. 
An authenticated, local attacker can exploit this via gaining shell access on an affected device and executing commands 
on the underlying operating system (OS) with root privileges. Please see the included Cisco BIDs and Cisco Security
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ctbypass-7QHAfHkK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?988a1f23");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq91055");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq91055");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list
(
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
  '16.12.1y'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "transport type persistent (telnet|ssh) input"};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq91055',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
