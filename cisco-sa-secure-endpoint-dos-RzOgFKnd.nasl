#TRUSTED 86c583bcea9a145544ea212a7244ff1e230774483885eeb7fea71dff8ed62ca29dc142b28d98fb7f7709faa5182d71b431631f7967ded35f5686bbf241937dc134a9e224c59b713200ef95ef4492f3942674f8468a7fd108e08b7fc99aa2386e59b84b1f5b953129fc5be05eb743c3626cf09d348481d1db128db147098de1ed76b67205d7701faf921e04d0caedb63c2b05d98c63a97051eea5f772e70e5f997f83419130aed515a999e5dcf1c1039a47fdd652bde10a2348cf9a1098ea5b0a67732bef11d2a9df85821e000a179703f487eacc3f05cc74d4da614f658e98f87f1d080af912c87e8958d40bb54d770175cef698433c5418aadb4ccfdefa4a87a61020589649ef2ce7d5e7e9c622a306366a01f344a36877e4537d908bf050f119c0e30d0e38ec8451684026020d350acdfc1eb7df70bb56fa94d650e32668e849ac51507e3c791f4148f3fdeb60b1125f6842bdf163329735929f7ab435c6904c624ddeae2ff747331efc961142105de1f12362fb289088e78f862312f14aa4d4ffb2395a53964dc2e068c48ce081d9a20407da2bcb50f19066f433dcdbfebc7693e714c6799b9b41cb6e2082f6bdbcf699e7d846be51a1d1eb5da1c79a42211f045e21b85ac9310ba6e6b8e208eb3333609791e665ddb77ec67ab699bd3d50b6cf8a8afbc1c2f35a0fcfe633275cb538cf45fdde05ffbcd9d270128e07b8d5
#TRUST-RSA-SHA256 23e759849f992f4e58325026575e103bf55d9547b5de700027c7db377b4649d10dac830c0bad5a4336a981b1bda72faad2bd8f69067361786fb51c6b42e8f64de66889d443a27723b82d1abf3f3d07ebb39c6cc120b4425a9fb65e807afa833c9e6f56ff81e220687359e438e21eb246ac00856b075442973f975d75398ce337b74b6a0f0ce7b90d169c57fa3b09b2241850b4411a7524bf6f23e3bb318c2b01f4288d7d990923733edd2467275f12562b3543bea5ec2dc7af1aeedc3d40e16dc2a05156419ca36b2c6191980129d5812e2a960a61ef5951cf18dd7c89515fd3333c8df8b49ddc76ce19d619c2d8d5462a106599e67f8968b76a69e4797585dfe7a5c7733fcabab96352fa5bcea16ffdc3dff3c696b1685b0ff8eae6ccc2080e3bef0b986bafeced8fe0b861dfe8c5cb3f7b66e66ede9162701c4d3af33747423894169bc34c85c4622d9d69727a2008f51923009027cef38ab518995bb61a936fbaea733e97ee023fb6977e3c86006fa0a5e46c29d7897e15271229e6d8fccb5f2f779a267bbbd821f08dbae4e6ba7953014434908617953f497d7c49e4a30032470197cb0f4ad245450804fcaf66dcbc6f48225d43b9a1311b4184e34b7c2b4221e92101b3365379d93504d912dfd7aefa3ea8f98682a253d2c49abb8179e6c68e1d5fa8e16f63d17546360cf6130cfe40a9d0f97df2e5b5fc98a01e79fe55
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187060);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2023-20084");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh78740");
  script_xref(name:"CISCO-SA", value:"cisco-sa-secure-endpoint-dos-RzOgFKnd");

  script_name(english:"Cisco Secure Endpoint for Windows Scanning Evasion (cisco-sa-secure-endpoint-dos-RzOgFKnd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the endpoint software of Cisco Secure Endpoint for Windows could allow an authenticated, local
attacker to evade endpoint protection within a limited time window. This vulnerability is due to a timing issue that
occurs between various software components. An attacker could exploit this vulnerability by persuading a user to put
a malicious file into a specific folder and then persuading the user to execute the file within a limited time window.
A successful exploit could allow the attacker to cause the endpoint software to fail to quarantine the malicious file
or kill its process. Note: This vulnerability only applies to deployments that have the Windows Folder Redirection
feature enabled.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secure-endpoint-dos-RzOgFKnd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?560b6739");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh78740");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh78740");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20084");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_endpoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_secure_endpoint_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Secure Endpoint", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Cisco Secure Endpoint', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '7.5.17' },
  { 'min_version' : '8.0',  'fixed_version' : '8.2.1.21650' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);
