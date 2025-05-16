#TRUSTED 0ff421f963d3a078524b98b3b0f17b63fe393f702c75d65602533aff744c9a86d52da2b6e3357fd1af4e4fb66e2c6ec5315d2bf3cb608a0e3d386b7e9e40b9e983e55ca8e97994de9d956ebc5f28045b04bd0eaa831bf4dce3893b459fcb8308bd238254be5d7f0e157d7f2e068d2e2f595a0eacb15ffd48f4c0b53d450f6fea4bfc02395a30d843cbd795127f3625a7769fa901a3d1b3ffe0cd3de35fc13889c4ca66834e9841e8e1032c9c74c97625bc6e5a79be6093ecc9b90d8d573644cfa86105c58d2c8642d4915933d0b02cb2b4728bdf3b5bf270a1fedd9694ea969976cca8a1c603897d920796d64cc67eefb8c01e5bc38f323e644dd12128369d0061995dc2816b186f9b17d924e335521ab82e28443314da5dee1ab4edc76edd5d2483f242a070e24391e6636ae4426158c3d124069357b119c03df5c513f46abf0f4da548b51a4d25b7eddba0b3615d55cb7da33293ac21311a721488b70b93cc2b2b61302023407c3a3f366b5bd9a6b4727c54f7d18d69249236ee05d524ebe5aba1608602107994600cd26ece203413034fd5e81851b3ccd56021b7e64776d49ea1c53b863b0346007e9716257698a2a81d5bf55ecac135c52da074147ebc1caee35f5f4323f84d9091a62003af2ec32eb72d1a1cffdd88246bab3222944c82954e114ddd9a38c01c0c7607b6e636ea54a6812d647b978a441d8bd071b09496
#TRUST-RSA-SHA256 7830d5955d76990f7c89d61ee68b5bbf99febd35df9cfa65914caf8b2f7559ed8f86337604734261490ef37dbce377fb7ccbefede1692e7766f7c9311c91fa36a6a5699df7583d0895cd2dd21f94b360064792943494118041faee5b74eee84312d798253c9cf5f3ea1e776a93097472ae1bb43344cfa0c4a06be8fd00f1dee0316b3f0b586be123f300e211e24106f24a910c45e70a687fd380acd94978e659e146b125e4aac5c861dc82a42c23c8b2482a0e441e65ac8b55f912a7023112d62357bbe47f64fdcc551e9e9ce23c39b7f48df0d0c4a1db1966ce770cb61effd6319303a94e045ec8e21a4995cb040baa2f0929732aff2efea084222df687d8dda2baad67be9da0145911814ac29f0698505b9eb17604dc5f1c6d06c6bdc8a57651939478cff7831ea9454ce69628038deba9b4d062e433820a9c73c8fa116ea9b1bddfde60e6278f31b569a423362153335cbe8f65fc56b343742fbb6e24d10a1a9ff5e61f0d6c07e6425005ea54d1405552d370794b72abfcb05e1445c89130c646b6115c34fde9d2b3d4a4c7e6197363d5272daa526aca1a3f498cead07aa9487fca5cecf6c40f1270bf8f7731d7594b7abc6250648561f660ff6a0759da9242cb1c60808ad4709bef788bd81f81b197bf017faa9b262b30a09f21177f4a468aad24617866d7840b3f27ab7ffd1515c7ffc17b4a235dea38d2c56eed14125a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129532);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12657");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn29244");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-utd");

  script_name(english:"Cisco IOS XE Software Unified Threat Defense Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-utd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1237229e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn29244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn29244");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
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
  '3.16.3S',
  '3.16.2S',
  '3.16.1aS',
  '3.16.0cS',
  '3.16.0S',
  '16.9.2s',
  '16.9.2',
  '16.9.1s',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1c',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1',
  '16.6.5',
  '16.6.4s',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.7',
  '16.3.6',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvn29244'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
