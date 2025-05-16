#TRUSTED 42c9c8afcd54afb15af4dfcfd192f41e586ef8a2939cff88cae12d003b79bc0d06fdd5ce71dbd05a89a7c080b482d5b6f3c72615ca8fa309101c646260c1565f52763dccee1d6338067334313f3214e8a10ca61b9aed56785c9a3c59212aa8933ba726a60050c80f0867141923c598153f31f9d631a76c968f774da845ef2d3cc81b0c9e903b085641d2dd2272764334c041b43c91f240640f4e353450c4d66adc3d90edc896e24ecd11018cc35a6f2a5170c56976777997f528846c283544be664eb81de2a4f8689dd5becf9051f296b4a819c44882f149a1dcb66d4b87f91f2d5790539092fc5402a6f382bf6a0d4f8fa66b146a0ba12797d7201aad293d8d79a34b4dded57036d8fc1d45f0328d62f87c8f18690baa1c2b59e6eda6c2248a03c0e7b74877949ec85248f3922db4a170f73023faba387e8171f467af8b69d9c9cf50c18a5a3125636563d3f7cd9b38600db46700f4b43987b673dc393014932e399e085e3ab4f1a3c3622eee838c4cc5d47c59c512fe39395c27f05dc89a3de512c9e134a32f1942bca59f8fa1dbd3427560ec7c172bf25af6f9fdbdbf257dc641ace1793f63bdbcc37e76785b89918a2e23bcc99a1bb01aa8c610cd816a4b885c4253e9f8d703020bc903b98f0e0d995aa0713b00a73816c8ad290f19c0de672674f889dd0d0295bda66ab08df8d61fda07f96099c49b3580c7d0e45934fd
#TRUST-RSA-SHA256 a059091677e26f5f9dd30c4c88eb4f2c3b55569ae44682c2506e3ba1437456dc39ef684c4a5bae133a1f93d46d3ea3536462c74f829a38caa28a3c51f43d115fac74af82c7d3fb16bb7c5ce1c8c380660c9ae842e83ec37e83721e2936a0ea6f3c643547b19071f650eec8927c52a03fd9f586fb81f0aa86e1cc52aa470a2e62974e04bb03912f13cdab6b1a2cc870f64dbc53e88440f345e813ecec658b396f1e4315d3e4672f214533248a324421b28bce98f4ebb7f676b0a069f008cfc31a4c1193f9d81157b65a69a6101866079e1c9311b07e573c28bfc37cd081e6e1c47d8715ee340f2c7c88e52ccb5a37d8b42683afd26d9c7dca38dea8be25b5bf70064cad6887606a3add05f7df0ffd80372585dfc89a748aff433e0d57ce218d6f39dae08312acd8431e56a7be4f7ea9b08fd1e32f8b64ebbc8b6053d09f10381d2ad98e7c1543422aa6b1796e2030a45bd242ad2dbd6b7c57c280d957a9dcc51720e7a39684fa8c6e51fb2547d87f27de8b35b87258c2ec910bb27e6622824dd84630c1823f407626ca5dee7db070fed4f66017f56b071b4816fec7690d8fc1df97759a58971cbb764d4a3b5158056c57464f96938504a756117f97f54b908f46a50ac7142396621cc3cf5fe4aafff4d9b597542f6ceb7848ea481cec806b80768e852405628b58aa55cca86d71760d1572c1f5ca1011243d358b61758b7fb5c9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23926);
 script_version("1.23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2006-5681");
 script_bugtraq_id(21672);

 script_name(english:"Mac OS X Security Update 2006-008");
 script_summary(english:"Check for the presence of SecUpdate 2006-008");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have Security Update 2006-008 applied. 

This update fixes a flaw in QuickTime that may allow a rogue website to
obtain the images rendered on the user screen.  By combining this flaw
with Quartz Composer, an attacker may be able to obtain screen shots of
the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304916");
 script_set_attribute(attribute:"solution", value:
"Install the security update 2006-008 :

http://www.apple.com/support/downloads/securityupdate2006008universal.html
http://www.apple.com/support/downloads/securityupdate2006008ppc.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-5681");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/12/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.4");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2024 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

# Look at the exact version of QuartzComposer
cmd = GetBundleVersionCmd(file:"QuartzComposer.component", path:"/System/Library/Quicktime", long:TRUE);

if ( islocalhost() )
 buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
else
{
 ret = info_connect();
 if ( ! ret ) exit(0);
 buf = info_send_cmd(cmd:cmd);
 if (info_t == INFO_SSH)
   ssh_close_connection();
}

if ( buf !~ "^[0-9]" ) exit(0);

buf = chomp(buf);

set_kb_item(name:"MacOSX/QuickTimeQuartzComposer/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if (( int(version[0]) == 22 && int(version[1]) < 1 ) ||
    ( int(version[0]) == 22 && int(version[1]) == 1 && int(version[2]) < 3 ) ) security_note( 0 );
