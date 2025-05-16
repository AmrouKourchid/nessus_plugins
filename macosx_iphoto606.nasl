#TRUSTED 7a1b325333358e0dbb0f161b7a1af5f0e0bcef2bdd7f7cac332b82eadf66d08e4583030dae7adb5fc2fa45d6d0e07b46fe4ff6b64adb72a97c63bc30a313243aa4d644859d044fceee8d0505b4045c90c1f9d647cdec5e6a05cc53a2aaccbf9bc228014aaf8fd1dab53e3f372e90b93ce086eee83c2554e9116ff936ba1780c0fb2a01995d532aa5c3223d0b52444af8b3954b8866bfaeef30727a91e7fae5f58bf8d07d9f822370db007456d219c7e189a952d4314474631f282e7959e08c5dd1ecb55543a8c71b264af249e31d5ea45ff90c76b75c5d0e107649393233a2cd1599f636462e0709ca321f094f686db9f1a9d7286ba585026a8d331814cb183785e8d9de9ded64bd95c22d559f4b140f8850add0954f83ec857fd84a38391948835e02fdbfa21fb365508622dbc237774fff9ab84f8727c03c58ccba2a29ac6c9144ab36e7ce492af87c2c42a07365d5f1cb14d88a0dbe5d64db1dffe343c9aa88b4a9e92a7d727070ab7a920d3581b113ae0f1e183d8c9593353199f030b6aa55a5d3abebe3636ceae247db4ddcf90e2d4bd1000dca31c4fc1b184cbdde9944e3c06f357ca0e09fea90f5154626d11d41276414972e53942947fd468e21968e3b3c5b455252a9c3b7faeb42c910e63b9b0d3255d5ed1ba5402567736123bcd26c3b1b67837b88069738b5cc8d50bb20c65af9c25c519ea8a610310895308ecb
#TRUST-RSA-SHA256 647ace62734c620d6b38f533e3654dbf19f396f258539c90ed5e6c399a164e60e8f4702908805debb156047b5f6f23967fd87879bdf659e020e676e4c4d56288ee3759c9cc0134e4309676e552d6f574420c908e54555b849d8ce0701fe75ad2f2a4b81eda567e6edfa057afdf51d90523d338685b3c96193e9128c5c9bc471ed144ec18f14e8e4bfa212a0ee68e0fe0fb175cf8e024f9bce819baa637cca852e37c9bdc3b691c43f9890f75a5fa7c1eff6544ecf3a778347c721d6806ac0d2e0e12f623b6595e8f1d00a8dc8f135009cdc7a9de555f3f59104f51a62c14a12bda210b50b8a3f4c9f14d992db02aa7d591407aded4b52ec23d029be4070ce5462aa1cabdfe9e2dca84d15f630a789182214532cecaf7a708a0fd07074ce600dd81f8e61bab3bb844028e39332acdb19b313dd3254cd1b8f2c919503af7d68e648ce7b0eb813298f38927f449052e6c2921c175035ee25e03d22aa3fba8fa027fc493bf3daf08664a722b881ed3485945c0e499657fef73b8bd9baf081279602cc75fd7efe54a549698449f75eb1095ebd2a93fc7e36d7e96860e1332cadf3fa8f311c85eeec887dac9d743fc250fa158c50b4b2a8eda3d9f6b05a5dfbbed1a6fc31c713d7e2f1c2a56858dd7029b8b636c3e8a4aa6f27e1ae2108868d1c0076dbdb1d8e669b568c39b1f2b262782958192ae108881358ebc6ca65c0f487a95dc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24812);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2007-0051");
 script_bugtraq_id(21871);

 script_name(english:"iPhoto < 6.0.6");
 script_summary(english:"Check for iPhoto 6.0.6");

 script_set_attribute(attribute:"synopsis", value:
"The remote system is missing a security update");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of iPhoto 6 that is older than
version 6.0.6.  As such, it contains a security vulnerability that may
allow an attacker to execute arbitrary code on this host. 

To exploit this flaw, an attacker would need to lure a user on the
remote host into subscribing to a malicious photocast album");
 script_set_attribute(attribute:"solution", value:
"http://docs.info.apple.com/article.html?artnum=305215");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305215");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0051");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:iphoto");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2024 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

cmd = GetBundleVersionCmd(file:"iPhoto.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
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

 if (buf !~ "^[0-9]") exit(1, "Failed to get version - '"+buf+"'.");
 if ( buf )
 {
  vers = split(buf, sep:'.', keep:FALSE);
  if ( int(vers[0]) == 6 && int(vers[1]) == 0 && int(vers[2]) < 6  ) security_warning(0);
 }
}
