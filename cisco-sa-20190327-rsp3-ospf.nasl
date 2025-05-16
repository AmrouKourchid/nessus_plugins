#TRUSTED 035b26ea9aedaaeae3757fd9a92e95658a835a273b579d391a7b78edac3ad5972c917841f1d74904c0f7c40bbc14478b88b15fe9ed2bf98f9df1371c35b0a888377766a3852d2ba7476c11b326e8dd11373190894ebf1ee3355482262bf03f63ed2df574f6ac03fa29c9cbb8754aab1c6d5ef7a1ea8ec811179bf61baf3390900231a4639e70e6e54ae5a629cc1e4687883a6bc6a9e31df71369cfe23098636aa00dab867cd8aa6f9a0ec93fe02caded77bf8af43e994df4975bf6224a8772235e5b97dd8e69f874c74d07db4a65081e0c6c7d6eee8d23f9ea970f32b8eb0ac213337b8c4bf9ca3ae0d010d198264e836c6a6befc5491321a86af3092bc623b82bf4dedaa12117af82f3f6605b4f2768e037702a7d6731937b0bf8c97254d8b718ee8ab91428dced1615462992f5b4e2c536afea9c32d83f16708102cc84811512ce65d4ba7c60098bf4860f602c9f6190bce0ca28394fda2862d89ab44af45f95262a89010f3de608ad44cd546a1fe248fc21e24ef839cc0d73701f9a5b7d8f07eb55e0001f0d31570b0cdace84fb0098c61cdd41934f609a2ce27535ae88683cf8bd30cd4f4bfd41dcad0d1dab0e0020f766e1446c8b8a5179faa42fa6a93ce8d4895ece8225c628f0df8297241780721d9f7fdb6efde9550eaa67e64df6dbed4d6844762215064a8c0151168e0eef2f7fa712c8f31229a96e11deed8b9351
#TRUST-RSA-SHA256 00e42fe1aae5e3757e8d0c4939a38ac096c9eda18856cd2d8d84bf74099cc9da7fabf01064d102179297801c67ddde67a86a2de228e3f020096e35e80f6cc094b79111c821bcbca8b251b4c082055283eb61817fefad992e420a2765e510ed53a45f73281435e2075fe3081074d54720301b47837df7c302f7714a0b57deaf803e86758f9f716c43dc98fefb9bbc1c69395d2418eab20adf162e8c404c00a468f252ceada9d6ce9684e2733d2a0ed7136cff72825c3a17ccf111f93ddddde33ed4e578e59b5435907cdd7ec5977ca08fb10ab80e9199bd1c886d882116289004021caf658bc3ad9353b76d63bd90e417ebcca09104d569d4f609e8f63da12ffdabd288c156698293790a117f94baa4e1794749352ae7612d8d8ddf52aabfd93388b1db3640dff1b0819aa94b9f3310bdd53ccfe167cbeaa148036f5d4d4d7a0fb4b7026b4a700ff6c04755c6f63326aed1e5fff89bdc82ed88c96fed7809834a91d6a715bff6b01d2ba7708a7a5026ccda6f3a2f410df28092cd8ea2f65c6ead2d911370e8319af10d20970defedc15b493e0fbfe0f90834659ea92a06818d447d9700b85d40bf305f7a7872f716f6afef10d922ca7db4b682d90908a0b38e7ae43a6e21ae440e568cf9bf614e68aae46a8b5141e8f4dbe58fa3f3085db615bf73de390bf30527ad26743a29bf4fc3d77199a899d83c809faddf6aee5cea0dbf
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134894);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1749");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh06656");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-rsp3-ospf");

  script_name(english:"Cisco Aggregation Services Router 900 Route Switch Processor 3 OSPFv2 DoS (cisco-sa-20190327-rsp3-ospf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the ingress traffic
validation for Cisco Aggregation Services Router (ASR) 900 Route Switch Processor 3 (RSP3) due to insufficient
validation of ingress traffic on the ASIC used on the RSP3 platform. An unauthenticated, adjacent attacker can exploit
this, by sending a malformed OSPF version 2 (OSPFv2) message, in order to trigger a reload and cause a denial of service
(DoS) condition on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-rsp3-ospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f440371");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh06656");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh06656");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info['model']);
if (model !~ 'ASR90[0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '3.13.6aS',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2aS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7bS',
  '3.16.8S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.5.1',
  '16.5.2',
  '16.5.3',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.7.1',
  '16.7.2',
  '16.8.1',
  '16.8.1b',
  '16.8.1c'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh06656'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);
