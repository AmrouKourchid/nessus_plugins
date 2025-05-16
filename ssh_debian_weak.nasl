#TRUSTED 1c7efbc4546e12a50acf631045bb90d7b119caf20b724cc10e6d3f5b9ee2d8fcbfe2bdc062f60fba262241c575ec3441b9297c02d55030b733ddfcf3dff872544f4d563a9ccbae59b43428024d424b8d46b392d2d8829652e5c28034f49be3db7ee62e2eab01ddd5d8b96428fe3ffda979241ee63a886c77ae1e9719bc7945a022cf9e7f47d5b74ee04d74de603d83c6f646c2e396a9f2e6eb72fe080010890cbfa9eac3c8c179f2adbcdc81a6c3f62cfeca0892db42c6c56814c109f007673108588c231cfc59ea5ed653763ef46fa1b15eb7491bce0a083aa8547b6d4f20f8b77a90a53fa4659a11942a4359d16ec62c73ab3b62b175276a84883a7210a777369622739cb1023932263515eace8deaf400743783ad780a7585f03fd88011e9014302eb5422cf324909e36b8272edacf031549119334ce975f4fb23c1ce1271b25f585f35b87d19e220dd14f8198f395a6ff6ae0b2f9e4af733828ac9ad470832368a4f88b4b439d18407e57525f11a2a5ff7403c02741582bd3272f8a2f0d274e91945b14487bfc9fc7c60f3ae459b5d5be4137c394e8e77446aba02c38ba1a11fab149ca7eec068b543bdaf94b2c2a6c2c9a58d564bcde569218b54a3ac03d48a2d409f9dd6e951c74b75ac0f06f00bdf610b51fd2bdced561de5a364eac4e81b2d44a4dd8e08ddbd43ab94f5b692a26e45cf50adaabda15c3e46f4e9b985
#TRUST-RSA-SHA256 0cad0d4b7d4b308ab8bf4713c037c311fdec9ce3edb92b70b05078ae6e17dcf95de9be41d3fbd5896faf3ddc17f4e5f9fbdcdb7b415a10fc6b3194322dfad60a23c8532c88bca75802491b6f179d4b460bf9304522c539be1b07857c9511a80b6a56e0aabcda00c18a6a22b10815034e4f953da0cd1195431d29ee959d6cce2f2ecb5099a2ab4ef94c31dd7621b21e6891ce33ea5ac67e44ab9b95d90cad4e3f72cacf396583dc4a51780ef2334c9513cb5c963b6c0d97668792eff62b3dddfb82f6d9c14a76c3056b93afa6671c5d9d3c50598df63f82c343352cb4a20f2357f649f9c450bc92af993f2f020d1b59e023539bd91fe29f437c59a507efb215aa9b27931efa352ef38fc76009c23451aaad342652ce9addb8c94304fae3a882584770b1eacea0046b50709a8e1951a53b27538ced9454450c27f7e59e044e937cb4820400f7c0a504029ee3f49cbc580145acd85615fb6e5e001c8da010f02c9a5044e13f59086d49f648ad7681016bcb52c72f6d6bde22fb77125170bac7add6b9b6e3308bcdd3da8fded5bcd9d50d270269b244df8a7e824c7f9a47bf1d5acc0b2dd629a7881d55e30cd78f9f3bd623db44ac6cbae3a8cd8b42d72429e87227f42cd6d1d82796400ecb40f867c4cfbda6ee520a36e3237cb4ab4c75dca7dc3023f23280a2d7253251656aba4968ed3ca56dce5e1efad72f2ef31c6b7d42037f
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32314);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);

 script_name(english:"Debian OpenSSH/OpenSSL Package Random Number Generator Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH host keys are weak." );
 script_set_attribute(attribute:"description", value:
"The remote SSH host key has been generated on a Debian 
or Ubuntu system which contains a bug in the random number
generator of its OpenSSL library.

The problem is due to a Debian packager removing nearly all
sources of entropy in the remote version of OpenSSL.

An attacker can easily obtain the private part of the remote
key and use this to set up decipher the remote session  or
set up a man in the middle attack." );
 script_set_attribute(attribute:"solution", value:
"Consider all cryptographic material generated on the remote host
to be guessable. In particuliar, all SSH, SSL and OpenVPN key
material should be re-generated." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?107f9bdc" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14f4224" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0166");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
 
 script_summary(english:"Checks for the remote SSH public key fingerprint");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2024 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


include("misc_func.inc");
include("ssh_lib.inc");


SSH_RSA = 0;
SSH_DSS = 1;



function file_read_dword(fd)
{
 local_var dword;

 dword = file_read(fp:fd, length:4);
 dword = getdword(blob:dword, pos:0);

 return dword;
}


function find_hash_list(type, first, second)
{
 local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file;
 local_var tmp_list;

 if (type == SSH_RSA)
   file = "blacklist_rsa.inc";
 else if (type == SSH_DSS)
   file = "blacklist_dss.inc";

 if ( ! file_stat(file) ) return NULL;

 fd = file_open(name:file, mode:"r");
 if (!fd) return NULL;

 main_index = file_read_dword(fd:fd);

 for (i=0; i<main_index; i++)
 {
  c = file_read(fp:fd, length:1);
  offset = file_read_dword(fd:fd);
  length = file_read_dword(fd:fd);

  if (c == first)
  {
   file_seek(fp:fd, offset:offset);
   sec_index = file_read_dword(fd:fd);

   for (j=0; j<sec_index; j++)
   {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == second)
    {
     file_seek(fp:fd, offset:offset);
     tmp_list = file_read(fp:fd, length:length);

     len = strlen(tmp_list);
     pos = 0;

     for (j=0; j<len; j+=10)
       list[pos++] = substr(tmp_list, j, j+9);

     break;
    }
   }

   break;
  }
 }

 file_close(fd);

 return list;
}

function is_vulnerable_fingerprint(type, fp)
{
 local_var list, i, len;

 list = find_hash_list(type:type, first:fp[0], second:fp[1]);
 if (isnull(list))
   return FALSE;

 len = max_index(list);
 
 for (i=0; i<len; i++)
   if (list[i] == fp)
     return TRUE;

 return FALSE;
}

ports = get_kb_list("Services/ssh");
if (isnull(ports)) ports = make_list(22);
else ports = make_list(ports);

foreach port (ports)
{
  fingerprint = get_kb_item("SSH/Fingerprint/ssh-rsa/"+port);
  if (fingerprint)
  {
    ret = is_vulnerable_fingerprint(type:SSH_RSA, fp:substr(hex2raw(s:fingerprint), 6, 15));
    if (ret)
    {
      security_hole(port);
      exit(0);
    }
  }

  fingerprint = get_kb_item("SSH/Fingerprint/ssh-dss");
  if (fingerprint)
  {
    ret = is_vulnerable_fingerprint(type:SSH_DSS, fp:substr(hex2raw(s:fingerprint), 6, 15));
    if (ret)
    {
      security_hole(port);
      exit(0);
    }
  }
}
