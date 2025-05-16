#TRUSTED 957ce48a7e54460c3b300989d122ebb8806c9d0d712930093267be6d53a627b4441d5bd6bb54dd699e00ae087cdc5d634bcc54e61469fb0992350b6a4fa2f6c406d2215f271819b240845d054a539be4c7de160a0f579e87c58e0d9e829f7bb76c0ff4636c87d6736a41c4784cc8b1c89d24205afd65f1dff216a03c4e167378933288543a9b8db411bf8a2cea0cb6a827e60ea887fba78c47cb402850f07766ae26a2294fdec424eea2db11492e4f9bea7e21fe9705c20d80f1feca883fe4fe4b056f8263408619802fc0896afbc7c6831d9ef2f85ca288b458bcbd7ed5db4b26aeaa48fe33dae7b70c8720253e76c312748595169dcf5f5ad0436e44ffb5e74d91f92405b085522092460ff601c6a893a89f89aec43bef13b5db377aba7eef50f7102624995674db5fe67eb34e6d8a47be52945c66d34fd96040afa02dd69221d9168bc29b1022d15d2e4d714c262b64a52664bc99d94f18b86a7aead8d5b099fd658b46cbfc5e226f90010776fd69f4f72659dd3a4b4e897a29dc2717a3cec7893f6eed345440fd2a6bd613d4695de555812b9a3f78edbb12e30a989ebfc2f6f19c56ee6afb3da9d0029e430d2bd2a811ce075fc1b63d129f364f0e80127f29604b19c8117b60f8928325c75a18899d3a185f5c3f3983de05b14aeacf71354b20d97a9e65124fe4262a216d0ebd95f98715aec0b4d2f0351f46dcd186b368
#TRUST-RSA-SHA256 b1903874130e856a2235e84b8a0c94192b62616035a6db7e2b8c557838180e8e52be026826839ac0e86ce96eeabe32112cdce6f337c58cb0d8a1e9d1e571a6339a3c7ed0132da704d1e2b47a394690c4e39e0072217f804e914c94cf87efd8ae2a7ecef7826622b423f48d552f2747c0f5a5a15553d210d0b2156fbc9f3d1764a3a0c18c1dc58aa3e3be60be62315947793d9e707dd91ed79bfd8f62b84ee6c96e651f31c9f69eb54ac8ea1288f9e9d9f703561cac5087f7f3a605964355952ffc0a5e2b1989bef5f694659c62db905d7b828d780d2a5db53c0480e8bcff41719b3d3bfc1871e31cb40d054cb29dbd43c842afd3fa1a85bd75fed51349079793cfb4622548a52952de97304179498b6028fac4b87ede9d5cad78b96fcb9aaa5cdf27a369486b2ab85d16c4f4206da2d8990fdf5f8b67ab3b71897dba0560c2ecec00e321d9ddc5bacae9fba1b688ee8111371fc9d4aaddaa1f029295c5f2cb4b5e2e123d8fe64284bf40605b7d0c0a5ae154e7deb335d38673a56ff4a5150df6422dff034e08ebdbb8b1a50ab08c496867999313d75fbe5d2f8671aa21b51cbc6900c13e95e084058bb60af4273032b8c92ec2453f7b57c51cfb9b3e8f32092913514da4e234937d30336935e83531c3fa3330c69d23215ef8fa5b87e08d099e18675deb57f1189c0429bdf1a213dc4ee2c9a62f4391fc329da3b0811988ee97
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129816);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12658");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf80363");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iosxe-fsdos");

  script_name(english:"Cisco IOS XE Software Filesystem Exhaustion Denial of Service Vulnerability");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the filesystem resource management code of Cisco IOS XE Software could allow an unauthenticated,
remote attacker to exhaust filesystem resources on an affected device and cause a denial of service (DoS) condition.
The vulnerability is due to ineffective management of the underlying filesystem resources. An attacker could exploit
this vulnerability by performing specific actions that result in messages being sent to specific operating system
log files. A successful exploit could allow the attacker to exhaust available filesystem space on an affected device.
This could cause the device to crash and reload, resulting in a DoS condition for clients whose network traffic is
transiting the device. Upon reload of the device, the impacted filesystem space is cleared, and the device will return
to normal operation. However, continued exploitation of this vulnerability could cause subsequent forced crashes and
reloads, which could lead to an extended DoS condition.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iosxe-fsdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7c8aa37");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf80363");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf80363");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12658");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvf80363'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
