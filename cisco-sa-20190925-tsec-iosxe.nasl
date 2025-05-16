#TRUSTED 84bf5701d01f5a5ee2ff90e32ab38354bf38604a8f0bf6c135440cc1f75d511ac83d166d966dd51686946ba57c6bd08d0473eeec948fc9d37667c9e5bc92a65f9f3385a4a6350efe512be6bb9af84770a2c2c40c068c4b2893b22958274026d41e750cb3af3b2904f48ddcfa13b530f2b6b2079f4f0a0ae4edea8463a30da90352bccd7b7f78481513a0e9bb4950283c914a4dfc0022eb838cc4a0bcbd89ceb10ea262f2dca94c00ccb878ecb01ac27f6a094920f21c335a9cda5da29e6f3d79004368f67e50d8a9cb4d50c3413a07e32523c598e7f517a2c883d61c7dbb55314a6d24181a1d585289f2bcb8d20d81f4ecebb59f7b8c6059b3e97e1f0f2f47060493333ec1b75a5a4d9c9ed59c90218f59310ce43690f2bcd06ed2d339adc52a14fb412ec09b322d3298529de094369a22e1fc63095b05e35641f6bed4350bf1771a765347f6de382d69bba02803df1959c101b92f18cfa6d8a01c2ca73eb08eb7e430061c6042a809a2e3efb818d6463c85390562ce68b813a91f6599d41dd7e8b60bb63dd6e5ddba86b57124c7c545804e6db0327bb87ca6e4138680e3137f3185c603723cd994da9867d940012bd1f9cfde1ac22c7c6c3028305b4a95a6cc89cdfef8187118087dafc0f7306ee24a03e7a13a01037aab89bbe542832a6ab15f47b1226005c2b1db74957677ca725ff02d1078189ce8fcfead312552fe213f
#TRUST-RSA-SHA256 90ba34bab00c2f51bc6ad0f43870dc3466327c593cf31170f322febd00c29eedc3cc7f2cc77c3a5eef526c081c92be632fcbf730802f63537acdd1fcdddaf4bc7fd6759269eb59ff84d01b59ca163d513aa624fcc5fef6c19eb33d3526d5ac293c0b50132d4a1bbd7e7887a51b88fdb36da567374e05d604d2c70e98399868ee4d4b461d4c5f1ea089ae6cbc9331021d61e61748a17761f058f0e56656a9d7dab79718f64e274c3dd89072f2a9db570a5a4270a85627c9b47f83d51b0d579fdab2eefbe9a15e02d77ee85d5c26f569dff173e27599bf1b2eaf6ace160a3e0f3cd7792e5b409cd7fa70376f148a21d10cb8e72a4a7fcd9e554e4e6c1f38aeb9417a624af949b20e851b9c61116bb3c14004cdc3c9b3715d4733e4caca6ac799677cc592d7d0d71ec17478cee33e31013c0c70e3103288778c68334aa9e54eb5fc4c4f5b594958d37d45fc5321538dec18ca33bb8edf55a57b8fc002d0d2a9ee397337f029fcb03210e520f5dfd55bb67ece741943965e1905e30081d86090946945ebc165d80e00cb4d793fdad74a455117189d44ebabafba39879dd1dec98c85af19c17861b60c8fd82577e8e6ca4e1a5127ec3e427931188058a04b5e7c3455e601dae241c896abb454c3d540525fbf30507feca1717aa2ffce98e7b7070614688c638be4169bfda85fff86d093b95ebb54f9250ea4251d732dabe220395e01
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129943);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12669");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg56762");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm92998");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-tsec");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Change of Authorization DoS (cisco-sa-20190925-tsec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the RADIUS Change of Authorization (CoA) code of Cisco TrustSec within
Cisco IOS XE software due to improper handling of malformed packet. An unauthenticated, remote attacker can exploit this
issue, via sending a malformed packet to an affected device, to cause the DoS condition on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-tsec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48ce2f62");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg56762");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm92998");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvg56762, CSCvm92998");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12669");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

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
include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9aE',
  '3.6.9E',
  '3.6.8E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.2E',
  '3.6.1E',
  '3.6.10E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.5.3E',
  '3.5.2E',
  '3.5.1E',
  '3.5.0E',
  '3.4.6SG',
  '3.4.5SG',
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SE',
  '3.2.9SG',
  '3.2.0JA',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
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
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E',
  '16.9.3s',
  '16.9.3h',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
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
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvg56762, CSCvm92998',
'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list, router_only:TRUE);
