#TRUSTED 5b14dfd01e45ae9848a8b8c547c9cd2b04fb2602540d20641fcefdc2714f1732d82711a0143b76c837639d8323e4b55f78e7aa372568219361b01275501c7d91eaed7adb82ca696b44dc6b14bf8331aa19730a2bd9c9a90180e65243813df19edb968bb37367f45a42e1d3ffdd27a4468c7c32302fe8e43571050d9490a05f041777bd72c1727573f6cd5a70f8a9058e146729f9e24f570a7f7d38910a199aeb419429949b82e48bb219968083598ca990cba61ee15f1fc619fa8c8bce43f7b0688a0ea0f25494268649a00d5a7279941c3842a41a54648fadbdda4be4ad880e84e39f8a00d444b9818901a773543dd83bc2dccc7b0a16cd8a1a4135d67f593e6b24f95ec55d2518dedbf2939156b794394916244b0f1bc9979575f46dde74c99a26699de7bbc92fd69897171d0da4524deca00556182cd2b40336d1522a373ba827d72abb36375d51b48350c509135c8b94a3ab4bd30dd66bbcf2e34628c3ca7956635ff8b5c6382a0f5330c5d2ac9572d41e97e67831cf3488d55306e912fe2bbde7300a1732a2b6960e8eac02acc3a22fd9db40777f2e299b2bfd2f73d1ae8a30926c459b42e5f91f5f440f4e77849595619a2b2719c3213f51047405f47b589d00c3ce22f4ad8d79cbd6a11bde003a45994452a5e5093459132b2908e84dda3daf6dc9489df356fe522e209cd49631a2ff7452fb181eb8191a4d813e2f33
#TRUST-RSA-SHA256 0db5fc18baa440de8f4a7a26726c8ce71bcaf539cbfd37de51db8f73e034426bae37767e3dbea30165d5c3a511b5f1fcd0ca18e38fc81ee6bd472e13c02a14bfeaa5d753405a3c82ed7fe79d00405912d25c2c53111a6f972ab0a92b0892931eb05dc9a19bb6aa035da756392d0478398cae32fa35c8e0bc224fd4860ba257a157d7a81d2d68df4224b57c3319f54e9f1639fbd04ccbd7b5ec697b8c8f2b6c813210540f9484403a5966b9c8c9c251fa568fe300caf46660d9af904e2e70960a5e32af316c492fe5be64f09d9df5a21474dd768d3c04a4b9261110c278204a5e5cab1e10d20e5b3c8fb2410f940506c25fdd2dab11dc871416b2109b2eca813939cecbb90f2d915bda38342161e4704faa3756c5c3486f0084119703b4cc4588e6457d5d19834a3d153c062a04fbd501a271a8cef2067591c7ef3b7c36835f030d5934253fc47072bf55f746233ea238852cff1eb74bc6ca77991b2a53046f4fb38de5805817d5645b4134998955381ebc48e1dc146592adc1daebd904fd8d72f18b397e857106da7eb756d61e73c457c301e59494884e647117a93c2ce75de2c20e7eee553b522834a62c7842f2c02e330cb0f8a0eafac3ebbe0d1d2bd720917fcd6dd9184412850e305f4c2302e15d716a7fec205ed490f7ff2f4b60ef90d76a8c1ffce2224a09e659d614662e74248a3cc95b9aeeaf4fa521229252143cb4
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include('compat.inc');

if(description)
{
 script_id(34030);
 script_version("1.23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

 script_cve_id("CVE-2008-3844");
 script_bugtraq_id(30794);
 script_xref(name:"IAVT", value:"2008-T-0046-S");

 name["english"] = "Remote host has a compromised Red Hat OpenSSH package installed";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a compromised version of an OpenSSH-related
package installed." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a compromised version of an OpenSSH-related
package installed. 

Even though this package has been signed with the Red Hat public key,
this package is considered malicious, and the remote host should be
reinstalled." );
 script_set_attribute(attribute:"see_also", value:"http://www.redhat.com/security/data/openssh-blacklist.html" );
 script_set_attribute(attribute:"solution", value:
"Reinstall the remote host." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3844");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/22");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();
  
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Red Hat Local Security Checks");

 script_dependencies("ssh_detect.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include('misc_func.inc');
include('ssh_func.inc');
include('telnet_func.inc');
include('hostlevel_funcs.inc');

enable_ssh_wrappers();

list = make_list(
"Host/VMware/rpm-list",
"Host/RedHat/rpm-list",
"Host/CentOS/rpm-list",
"Host/Mandrake/rpm-list",
"Host/SuSE/rpm-list");

flag = 0;

foreach item ( list ) 
{
 if ( get_kb_item(item) ) flag ++;
} 

if ( ! flag ) exit(0);



if ( islocalhost() )
{
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if ( !sock_g ) exit(0);
 info_t = INFO_SSH;
}

md5 = make_list(
"00b6c24146eb6222ec58342841ee31b1",
"021d1401b2882d864037da406e7b3bd1",
"035253874639a1ebf3291189f027a561",
"08daefebf2a511852c88ed788717a148",
"177b1013dc0692c16e69c5c779b74fcf",
"24c67508c480e25b2d8b02c75818efad",
"27ed27c7eac779f43e7d69378a20034f",
"2a2f907c8d6961cc8bfbc146970c37e2",
"2b0a85e1211ba739904654a7c64a4c90",
"2df270976cbbbbb05dbdf95473914241",
"2ff426e48190519b1710ed23a379bbee",
"322cddd04ee5b7b8833615d3fbbcf553",
"35b050b131dab0853f11111b5afca8b3",
"38f67a6ce63853ad337614dbd760b0db",
"3b9e24c54dddfd1f54e33c6cdc90f45c",
"3fa1a1b446feb337fd7f4a7938a6385f",
"41741fe3c73d919c3758bf78efc437c9",
"432b94026da05d6b11604a00856a17b2",
"54bd06ebf5125debe0932b2f1f5f1c39",
"57f7e73ee28ba0cbbaad1a0a63388e4c",
"59ad9703362991d8eff9d138351b37ac",
"71ef43e0d9bfdfada39b4cb778b69959",
"760040ec4db1d16e878016489703ec6d",
"89892d38e3ccf667e7de545ea04fa05b",
"8a65c4e7b8cd7e11b9f05264ed4c377b",
"8bf3baa4ffec125206c3ff308027a0c4",
"982cd133ba95f2db580c67b3ff27cfde",
"990d27b6140d960ad1efd1edd5ec6898",
"9bef2d9c4c581996129bd9d4b82faafa",
"9c90432084937eac6da3d5266d284207",
"a1dea643f8b0bda52e3b6cad3f7c5eb6",
"b54197ff333a2c21d0ca3a5713300071",
"b92ccd4cbd68b3d3cefccee3ed9b612c",
"bb1905f7994937825cb9693ec175d4d5",
"bc6b8b246be3f3f0a25dd8333ad3456b",
"c0aff0b45ee7103de53348fcbedaf72e",
"c7d520faab2673b66a13e58e0346021d",
"ce97e8c02c146c8b1075aad1550b1554",
"d19ae2199662e90ec897c8f753816ee0",
"de61e6e1afd2ca32679ff78a2c3a0767",
"dfbc24a871599af214cd7ef72e3ef867",
"f68d010c6e54f3f8a973583339588262",
"fc814c0e28b674da8afcfbdeecd1e18e"
);

res = info_send_cmd(cmd:'rpm -q --qf "%{NAME}/%{SIGMD5}\\n" openssh openssh-askpass openssh-askpass-gnome openssh-clients openssh-debuginfo openssh-server');
if (info_t == INFO_SSH) ssh_close_connection();

if ( ! res ) exit(0);
report = NULL;
foreach md (md5) 
{
 if ( md >< res )
 {
   line = chomp(egrep(pattern:md, string:res));
   split = split(line, sep:'/',keep:0);
   report += 'Package name : ' + split[0]  + '\nPackage MD5 : ' + split[1] + '\n\n';
 }
}

if ( report )
{
 security_hole(port:0, extra:'\nThe following packages are vulnerables :\n' + report);
}
