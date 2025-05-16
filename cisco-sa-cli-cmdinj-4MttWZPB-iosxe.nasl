#TRUSTED 85742419efc92a72a50f91e088925c845ec7fc5fd794a31c507e7c7f72959c5f56261903adb5f9689f412a1b7d34a8011ffe70f048c13f2bbabf5604e5b25cc0acb3fa87d77e558ca01afd6285f950934114ceea4499a038a06ad53e1f4f9d477cc6cf682fe0da71299f8678eaa3f54e77ef666b199710bc7530af86831f98d4d76beaf390fde7079810dd76516a06ecd4587bd4bce771ea57e88b2a6d2d46de383845bfbeae4e798f9b82008b4eb0ed2e7f497b640d39d71490f84460f068dea926373d0a1e956a01712d45b6b064d33bb7b0f91e426d35decfdc2e57e7f25f7cd0d160f22842a089452ae6d0e356b40d4616cd1059216b0a607ed501d991512731bc8a20f716d90d7135621db3efe4b89a287d5f83ae44ca648cb8666656494c9e6b63f50229eec435c02baf9bc7f694d47c2df9d7fc769e71778b25e140102715bd4ed8e3d9036bcf5eef082cae8559d6cc78806954244abfce0b4a175ebacf44a55e46556e56bb8cd7c6fdbf7046646928233278642c356f9388f19f8a21e4c494a86c04bc574580ed65fd60bf07896dc299317b7d6566fe1647f578b6530a882fb263a58cc8331e964c4ed1e80fcd44ec085d10082642b82bb4150724e8f3789db509700dfa252c8be9b2ea90a54f06ea890845636f9fd3135f656f75f8ffd314d29c30561450ea5e3d335bac1d2454cb560652450a07ea46ea14a14a52
#TRUST-RSA-SHA256 98ae1c6fe2870b837d31627ac7b120ec446540654163d8f3732e1cac19c561fd711d76bfb0790cdb3d212b0539cd5cd573949c8d7080757eb495310834c3cbdc34ac820b6d5bcec76f8f718bde20f36e6d47b994d6df5d48b8d0775323e430134d8b93fde407f4962c43ebe1430b9eaa98e3ad7d60fa8b290842ace84cc68221584b5ea9f3f9c2d4ae9ebeba847e724fa38beb844e72db6bf6c42dbcec155564ae59e264515a4a49f3b1ba03bbaf86a969d2f54979db318c4661629bfed990e6148c5cf303250d33e828d525a0966a0e2fdbf6676a61f0ab4478417f535d3cfcc74cf336527a8a1f872b20e624c70ba35b7c88c1454425fc507b9ec82f3465fdad2206e0e65392c58793a9a4fb4fba859edba763820c2be264cd312720cf85b9446afe9b787ccd6acb6bb3dd1369386c55668c0e642fcc7b83f72996164dfc91ab2926f3f025b0515b41f45ea261eb5280c5860d2d453204667c57cf5acc9efc2a56667102e462f903611ea0e48b9f9ce890be562017771dd1db21aaf7c6989d6d28bb8c6896cb72623093e1721c1acb70f7df2933255032f1ec168b8e6828d48a68ff92a6c9b9941da11a173ec66656d0852c3f03e7d35d6c8b56da1e2ec222366effcae104181c940ab7e979b6146b31e941f1fac464e95aa1ad66fd7f4337aa6dc94d9ecaa66db606cce9404339738aeb9312eb4e538e4ec3e91ee126ad71
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156884);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id("CVE-2022-20655");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm76596");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq21764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq22323");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58164");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58168");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58183");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58204");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58224");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58226");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz49669");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cli-cmdinj-4MttWZPB");

  script_name(english:"Cisco IOS XE SD-WAN Software Multiple Products CLI Command Injection (cisco-sa-cli-cmdinj-4MttWZPB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by multiple vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cli-cmdinj-4MttWZPB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e56d38ec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm76596");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq21764");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq22323");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58164");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58168");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58183");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58204");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58224");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58226");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz49669");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvm76596, CSCvq21764, CSCvq22323, CSCvq58164,
CSCvq58168, CSCvq58183, CSCvq58204, CSCvq58224, CSCvq58226, CSCvz49669");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe_sd-wan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

var version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
  '16.10.1',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '17.2.1',
  '17.2.1a'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvm76596, CSCvq21764, CSCvq22323, CSCvq58164, CSCvq58168, CSCvq58183, CSCvq58204, CSCvq58224, CSCvq58226, CSCvz49669',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
