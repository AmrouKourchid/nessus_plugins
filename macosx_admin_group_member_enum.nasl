#TRUSTED 30f5a2c0f4255f2511692684d01a73c5c1e1d6ba85b4799905ad6f4c3b43286208e67dd5f3bc583b5a2eefa902ed43c4a01004ebd4998241645c28883b15e022ee8fae4c0f7154f719a4fe5f12c9ff2cf2368f6ce695d9a7602c572deb6f5c35c24978ca4a17c569fa32ced7d966dff8adf1da81e6a3a2bc1ac22e27e74c59f7d3b62d578eac4986f4ddfb7085b09e74def092d5e3a1bdfc43cc3fc10e866ce8ed710e82b754860b1f68f5ec38403d8e2e5caf1c552f7a5bf224537d38147daa8a081aa7d14bab149c152c2ad0b2e8758b834c0e57e18f06dce6650bdff64a941dd229edb5cff223525f7b01acb9f7f428478dc0ed42db00621872bb09921f868a356241dd798b66814156f04a19eccff8e96071b9c16e1bdffcbbed0014842bebd7521b3bd98469c8a39ac13408e5b939545b2cb4f93cbb92c848682e3f7e8ead32252ebbc5e13e8cd357ec2bc477fddb55704d1593fd8bd9ad794dc23c0271da5ad297829b320eaad66b6717b0d00059e399e2b7ea2ccba9034fd17591d850effe245f61416ef41d3b1e85ecfac2d4ae36f13c8a9970255ce529b5077cfefa73e5d8df1c35df24b3347ac775a89ba98df4c8990ae8db51fd8e0477bc2d6f49cf89191ef1f8170ab666301ce95edb6196b8f6889a8432fbcf04f3ddc75bed57e16377032087118ddca93d46bbad6d4d091a69d2a7605cf20105de12be424995
#TRUST-RSA-SHA256 256e0c8ba2fd312e1e64e93e803b9afbcf1d0d12a5c22c41f39423d02a9f0872812cd607859879288d121f3c1887a1f44d1b8a17b87eeff550b67047eaf70843425e445b51a37c7b1486668c6f14b4ad08b86cf4c0505ea86376612441457426a9c2c09cd2e868928cd213ef3abff64859c4b1aeadde74d14234c4250a1ed2aab3b4dcb35e91eea267bf7321740971b3019d1f4ec22b08fee0e3bc341eb4b4b64bbc870b07b15abe288281b8a8600d6b1f1bac5588e792bda1f854515535e71ad85ee5e8ac195ea88d45aee79a2a843fab72ceb38e66e2d7d4fa2ca2e228624f8d1a92b4ddeb324c5660d3f86d1f217c01dae544ad008c10ebfea34525d33b6f2ef7332de215bd32b13f6a462d4ace4075d7652ad54d511c209d3c494a19e2790702d39b39bf40910290355a78bc165962b10c054beed21945ae5be7fde0413bc0e04a674afd453f12ce82ad47394f1beeee96037485e0d53932ca6bd674e4065469448b577f24b070da4d2230982c1674a81a8c0590ca8bdb5bdc33fcc6f2336615f93a1ea5d108df8e343093be26b0e4b79725cde0ea15c00109c1aa151a96457137b0df515b89186a6b2bda031f5ce80fba8b0a7cc31427af107405d85039263eaf0bcfd4ef1f4f8652b8807eacc3191df5fe153319ed90c0652444e8d8902bd09b8960e3f8bac5a30a17964c9f1a536438c43f83b7923e8236b0351a373d
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60019);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X Admin Group User List");
  script_summary(english:"Lists users that are in special groups.");

  script_set_attribute(attribute:"synopsis", value:
"There is at least one user in the 'Admin' group.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to extract the member
list of the 'Admin' and 'Wheel' groups. Members of these groups have
administrative access to the remote system.");
  script_set_attribute(attribute:"solution", value:
"Verify that each member of the group should have this type of access.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("data_protection.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");

cmd = "echo ; /usr/bin/dscl . -readall /Groups GroupMembership";

res = exec_cmd(cmd:cmd);

info = '';
info2 = '';

count = 0;
if (!isnull(res))
{
  blocks= split(res, sep:'-\n', keep:FALSE);
 
  pattern = '^(GroupMembership: (.*) )?RecordName: (.*)';
  foreach block (blocks)
  {
    block = str_replace(find:'\n', replace:' ', string:block);

    if ('RecordName: admin' >< block)
    {
      matches = eregmatch(string:block, pattern:pattern);
      if (!isnull(matches))
      {
        if (matches[2] != 'unknown')
        {
          foreach user (split(matches[2], sep:' ', keep:FALSE))
          {
            count += 1;
            set_kb_item(name:"SSH/LocalAdmins/Members/"+count, value:user);
            user = data_protection::sanitize_user_enum(users:user);
            info += '  - ' + user + '\n';
          }
        }
      }
    }
    if ('RecordName: wheel' >< block)
    {
      matches = eregmatch(string:block, pattern:pattern);
      if (!isnull(matches))
      {
        if (matches[2] != 'unknown')
        {
          foreach user (split(matches[2], sep:' ', keep:FALSE))
          {
            count += 1;
            set_kb_item(name:"SSH/LocalAdmins/Members/"+count, value:user);
            user = data_protection::sanitize_user_enum(users:user);
            info2 += '  - ' + user + '\n';
          }
        }
      }
    }
  }
}

if (info || info2)
{
  if (info)
  {
    if (max_index(split(info)) == 1)
      report = '\nThe following user is a member';
    else
      report = '\nThe following users are members';

    report =
      report + ' of the \'Admin\' group :\n' +
      chomp(info) + '\n';
  }

  if (info2)
  {
    if (max_index(split(info2)) == 1)
      report += 
        '\nThe following user is a member';
    else
      report += 
        '\nThe following users are members';

    report =
      report + ' of the \'Wheel\' group :\n' +
      chomp(info2) + '\n';
  }
      
  security_note(port:0, extra:report);
}
else exit(0, 'No members of the \'Admin\' or \'Wheel\' groups were found on the remote host.');
