#TRUSTED 35996e98f611c56924eb7298c581a093c10ddffff3dfc183b4f127fafbd5c9a6c34639adafbfc8212c43a391ea7f93f9c554775efe6c3a9443f836c1c4b4bb160af1228388aacd5d9794f8414432b218f72fb33f83f7966e22adc133ef9d2cc80858ab507700a900228b25d8f15d916440a15b4d0b36f7001278e2355576b7a4b7f6fa3678fe2edaadaaf92f1c356014110f784e1d422cccc7090830d18c9827a2df91f6ea00cd51580b7f3fca017d2ef7e81647af3608c9b72655e170106593468bd328b878e7ecde83804d2efdd7c871ed1a6a921afdb9137c17d997551ff0f2a9b5c609de621dfa707a7d9846c17748ca517f2b4f3bb730df057deeda271bcf3e6d7e24082133abec80bd3822eddf7f7195725c4b2eee21099a24d4112ef4a4f48de6263587257bdba06009eb9a798df94354f913b671fc3559870680dbf5ee8c080071bfc06697b814116ba71e462e8693c24e1d7577abc9d26e02ab50457f6f6b30c59070cf52c81a68e0e28c031a79f167fb14d66d999c2664deb33ea3e39c9d156ab110ec08aaf4b26b068d138d1cf02bd59cc59109bf30ff7e9eb16c6fc912ff4585322e08bb9963e2b7acad6e35ed5e7cd4597e3e90adfa23fd55eade7881add0c9459a3406d549a44eae3a9e3e9279343d0ed859813e90b56d93fff72f89db1449189c7fb6c9dbbc42715e2e4d2aafa6a3055666047cf9e8d83220
#TRUST-RSA-SHA256 04ec965515479759e848a98d84a09b59ddce6340bb6ad0327ff9f5f86ce7c64bf8f7225df14bb82c55c30542b3840365edd0b97af212cf0264e215bcd6d47b06c228230c7c522f18dc05cfa09ec53e563fb718474207601d7c9aa424df7cbc729f244af7c0c2b6c8a1b634ded096f2e895da4e7d9441aa09dfbabf1a48a1ba4e49daa345bc4bf871c1bfab78c784b154ee8c6a3c460e9dc0dce8e3f5ac49231de2f0669ed75fc5dbfd3f45c6f6f4ad52759d6950c97e8529a7e63ec8e3a87f1c88e787245d27d573ac00981a6c40a0ceab871113a02ed108027dda9289cbd10774689ec3c67c9f56939b35e24434332d0f952cfce64f6094963f8506b0732e111510d8c6369edba7089ab9050f5f66aff7c3973082d999601482c9867a13d8f8f9df507ef0a38675a13e24f90309b504f15e8f225ef4f415335a8c7df5243ac9ab9d1e0d5778e908a6face92434ac3d2401513c0a8c870b82ed093953facc5b57a0df9f44b2bcbd11cc9e2516b16ea06026549dd591fa621850d4df18039f08ae7abfc80b740db301b41b06355acc2c826cb9f420ead5eacf97fe9d1f3fb9a7a77f40c3e3c7bf6d07851eee388b241e8b7fe05f9793e932fd8ee1ed6022b7138704f30ebb1e80ecf9ac69b1976840dbfc979ca6cc474283a1044a929c0d07df8b7aef9d8c3da21f4566eeb8a67af57bfab3e04774eed53898cb172c2f05836cd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124277);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1746");
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj25068");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj25124");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-cmp-dos");

  script_name(english:"Cisco IOS and IOS XE Software Cluster Management Protocol Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by A vulnerability in the Cluster Management
Protocol (CMP) processing code in Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, adjacent
attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient
input validation when processing CMP management packets. An attacker could exploit this vulnerability by sending
malicious CMP management packets to an affected device. A successful exploit could cause the switch to crash, resulting
in a DoS condition. The switch will reload automatically.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-cmp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69f78412");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj25124");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj25124");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1746");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  "3.9.2bE",
  "3.9.2E",
  "3.9.1E",
  "3.9.0E",
  "3.8.7E",
  "3.8.6E",
  "3.8.5aE",
  "3.8.5E",
  "3.8.4E",
  "3.8.3E",
  "3.8.2E",
  "3.8.1E",
  "3.8.0E",
  "3.7.5E",
  "3.7.4E",
  "3.7.3E",
  "3.7.2E",
  "3.7.1E",
  "3.7.0E",
  "3.6.9E",
  "3.6.8E",
  "3.6.7bE",
  "3.6.7aE",
  "3.6.7E",
  "3.6.6E",
  "3.6.5bE",
  "3.6.5aE",
  "3.6.5E",
  "3.6.4E",
  "3.6.3E",
  "3.6.2aE",
  "3.6.2E",
  "3.6.1E",
  "3.6.10E",
  "3.6.0bE",
  "3.6.0aE",
  "3.6.0E",
  "3.5.8SQ",
  "3.5.7SQ",
  "3.5.6SQ",
  "3.5.5SQ",
  "3.5.4SQ",
  "3.5.3SQ",
  "3.5.3E",
  "3.5.2SQ",
  "3.5.2E",
  "3.5.1SQ",
  "3.5.1E",
  "3.5.0SQ",
  "3.5.0E",
  "3.4.8SG",
  "3.4.7SG",
  "3.4.6SG",
  "3.4.5SG",
  "3.4.4SG",
  "3.4.3SG",
  "3.4.2SG",
  "3.4.1SQ",
  "3.4.1SG",
  "3.4.0SQ",
  "3.4.0SG",
  "3.3.2XO",
  "3.3.2SG",
  "3.3.1XO",
  "3.3.1SQ",
  "3.3.1SG",
  "3.3.0XO",
  "3.3.0SQ",
  "3.3.0SG",
  "3.2.9SG",
  "3.2.8SG",
  "3.2.7SG",
  "3.2.6SG",
  "3.2.5SG",
  "3.2.4SG",
  "3.2.3SG",
  "3.2.2SG",
  "3.2.1SG",
  "3.2.11SG",
  "3.2.10SG",
  "3.2.0SG",
  "3.16.1S",
  "3.16.10S",
  "3.16.0bS",
  "3.12.0aS",
  "3.10.4S",
  "3.10.1sE",
  "3.10.1aE",
  "3.10.1E",
  "3.10.0cE",
  "3.10.0E",
  "16.9.2h",
  "16.12.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['cluster']);
workaround_params = {'is_configured' : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , "CSCvj25068, CSCvj25124"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
