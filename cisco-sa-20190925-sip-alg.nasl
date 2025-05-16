#TRUSTED 422f0dd559ea95f86abf08bf374bd542e332b290a0ea4cce456da280a21feb3c2c2775fe0d0e68e5afd09423bbaa92e5659c7b645979b798162b86d2b80a98bdf925a83cdf78f836f0f3952b2f9cd7fcc17920965e8d2c2a6ab915558a5fbb44af0d72244dd5d7564256940a14488dba49f70e62124467cce3da767e1a7f785b6c3b6b16eb136a62061da5d28229e0f12993fc1dfd53357c089aa4edf53081012e69520036ca79fbdfb18ac6cbf7e95f10e33557945dcac642e564c67a9c9b65ac2d11f7ee28e0a43e73a67a0325cf821e48a71e750e6ecef5ee4c85c90b373eb55285bf3a40bf7b50e42959b28c0c012bfa8bcbbb347f90de4f64c4953a8174718daa9098e4a61b427fa505188db5aa2b754b517bf17b4ba563820647181ae2162383a0fc16d86f9627df829a70635fb09b177e056fc7684817c31802c900ffaf888e340f4fad964fa4b3944bb125786ccc0ded54ce892a4966612653d190fd9b34be793113e2395c7b7ea8b9664176ea63a6c9206d844e4bc07a6c8ecb95b1fe1ca97c80f709dabd3db93881981191f96462b594717f379a2afab0ee3ca73e7886e102cf069d88c15191598d95ebddbfebeadf9e6a4df848513865534ce7181dab9bad5332e69582782792203324d0f1fe4b067c4db53934a7f7eb31accec42e9730f1e7c3ae83e2552984ee5a53e8d1a3372e31f25b5dad271eaba18561c9
#TRUST-RSA-SHA256 1e612e7cee2671f1d8916c53551456b92851d77a7d974481ee3b63cbc881026f12a0c90bf787d9708bc53070694d7df58987aab1378cee18863a0d5f0ad192c13825112684e7709f8aa1652537113918836dff09f4279682a79cc221180c073576875be5e8a4594b4c90647f9ffb7e76f1021de693a7d69ff94ee5204ccbb97b87f613b83bf24e7cfb917c75f5eecf39a2c4814dc05e4ba58d08fa5fc3b8caf404874c07463cf19e33112dae74ee33dcb8723d585a12237048b7b3497a2e5fa8ad5fe97845a003d3317095b3695e3a4569b353754d4b21295ee90c9c2301832e6f93ab325b34a47c875b4fb405454613a17781794f1c659944545d039ade418c60da93ebb7c2e483fb034d73990dacabdb25b5ffc6d4a0cca52693af9d4a33fb84e191def3e0439f2f3c01e230eac8666ccac0d834691efe99b27930abb701c9a931f3272a385f708656927f816222d7d25eaeeb041b170f1971b40b5e1b1a2aa512de2bf2b41960743d57edb6cfb61aa330a4c558389f7a50ece89c2bcd94303171098473dc4bfe56a1988b7838548cda5957b97e7ae8de95c1d89f36b214b3ece836ba6b25f3c9a47b5a6f48cb99543c1de5ffd9f6dcd19f1309b85a83c0cc8855d0fe4c1456fde186a1d317673dd45c8ffba24b5f673951a5b3362ce1505c565e649033380caa6c3f344ffc2f24b2fb0c250c2fc184b9a71f6231b1f943ef
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129780);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12646");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn65912");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-sip-alg");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software NAT Session Initiation Protocol Application Layer Gateway DoS (cisco-sa-20190925-sip-alg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the Network Address Translation (NAT) Session Initiation Protocl (SIP) Application Layer Gateway (ALG). This allows
an unauthenticated, remote attacker to cause an affected device to reload. The vulnerability is due to improper
processing of transient SIP packets on which NAT is performed on an affected device. An attacker can exploit this
vulnerability by using UDP port 5060 to send crafted SIP packets through an affected device that is performing NAT for
SIP packets. A successful exploit could allow an attacker to cause the device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sip-alg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82cd252a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn65912");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn65912");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12646");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info.model;

if (model !~ "^ISR11\d{2}([^0-9]|$)" &&
    model !~ "^ISR4(3|2)\d{2}([^0-9]|$)" &&
    model !~ "^CSR10\d{2}([^0-9]|$)" &&
    model !~ "^ENCS"
   )
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.4aS',
  '3.7.4S',
  '3.7.3S',
  '3.7.2tS',
  '3.7.2S',
  '3.7.1aS',
  '3.7.1S',
  '3.7.0bS',
  '3.7.0S',
  '3.2.0JA',
  '3.18.4S',
  '3.18.3S',
  '3.18.2S',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '17.6.1',
  '17.5.1',
  '17.4.1',
  '17.3.1',
  '17.2.1',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['nat']);
workaround_params = {'sip_agl_disabled' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn65912',
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
