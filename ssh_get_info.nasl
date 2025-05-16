#TRUSTED 6788d7c92e69977be8b24abae97e1aafb62968822c9fa7c52124a7473da16929d05daee06305987bf2b04c66c6054f66ef07ca4bc49e19bfe4d08970a2815ed1f73e6593d8a7808aeb62a2ec990a9a12ba6e8dbb29572fef7c9215d7cdc7d0d8cdd555afd9e476086fab58760b9a97b90cf9ff4c514dcccdde48687ef021354ab46e7e38bc5d4d94ea91b703b6bea0ff0544d110064a1518130f663e24d61ee73b25199cf4498fbe5799c450a9b1a2de55d19c12f7f3a6e4d01508c617a1725286959ded8efbfb98d017f79b6d18ee8a857c0006b9b6e5ac49c55bec945cc79b78ee666307fbcdbfb10ec4e6ca70a00574db513c4a606b871012cae6316856fcb0b041cd27736046c335273e78385923298366667cf4f700821529e131be619ef617c4477e8027345e46ab978f7ee6e89ec2e6eb6e16b81a4c64af2269d81aff8a00e19c122de2b700e5b3e2c09fb7480fc2ba49ce04356ccb13b145617c8a45df42f54ceff081f29ac604ea9b81ebcd868e54fcdb67ea2f60cd88050f5bfd986ef584e8fa60cd6392d5efda35eba8b50bb860c919e6b42c4856be97758ca4644d901ab129628251de4cbe52c097824034374704c2442a3d44d30f5ccecfc955b10d303cccef7eaa6fe43f8b44726371f0574364c0eacb9b4b214d1c1e080fedd9f5c79dbe7fc90d4943c2359ae7dc98fb52c7de68dcc76253a4e77328b98b69
#TRUST-RSA-SHA256 51fd5bdea7e8f4c7cbb33f392129542cfc51aca8fd770240949bf4f929b0588fef368ad750953ec4436d66c54b771115912821b2670b8513009f2aba4642fc5eb437af64e537bdda40053b267dbfd185b7a46739dcfac74b2e89f3866f4ddd5dccf88156037e6ee7eb93392416389b7de963ed79ee3835b02bc1f9944584d7319f1319d36baf3d331aeb03e4a1e8a23b02726433eff85b32344de7b0d2dccd68153c7bf944c1b22bf818dc44635565651c2b42f59a6ecbf40dd796a4bb4d482055cf1af850c3c545bf438b6e12e5ab5b57cf266ca82859df1b664d88149e53a1845a97bd157d7b9b9f17a74983b8519eb057149847411e9a92946354f09c1e1287edbceb84cf9f372fa481ae3252043bebb568e9b8212ba2acfc59b2ed4606361c70b79738ff38f9319b469411b26c02cef901766a062a989c44f2799313bea027f61c6208d49b5bb3a04063339110856ddc552f1277ff51c97868fccacd181094e430171e2053aba7a34c1606d4b07f5b5128cefee046440a58a9d45e3e9c54df5f9e143572966e2123a97fb2ac04c3b179ba22358f8d53fb0e2fe375cd96a7d08dbc6f978fa2c3a64b4f30526942facd31f18d6efe26530d9a926c72121967dbdbe52ddc5724985d231cf821ba9ec018139a2c059a0acf22c504e11f670e8627073494cdc475f0652c03d6b1445812592b496b9bddb0626c9f1b27eeafac53
##
# @DEPRECATED@
#
# Disabled on 2024/10/02. Deprecated by ssh_get_info2.nasl
#
# (C) Tenable Network Security, Inc.
#
##

include("compat.inc");

if (description)
{

 script_id(12634);
 script_version("2.429");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/15");

 script_name(english:"Authenticated Check : OS Name and Installed Package Enumeration (deprecated)");
 script_summary(english:"Obtains the remote OS name and installed packages.");

 script_set_attribute(attribute:'synopsis', value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:'description', value:
"This plugin has been deprecated by ssh_get_info2.nasl (97993).
The new plugin uses a more modern SSH library and covers a modern
set of SSH targets.  All existing coverage has been ported to 
the new plugin.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Settings");

 script_copyright(english:"This script is Copyright (C) 2004-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("ssh_get_info2.nasl");

 exit(0);
}

# The nessus engine will remove any plugin that starts the execution block with an exit.
# Because there is no way to synchronize generated plugins with a normal deprecation, the
# following has been added to implement a "soft" deprecation and will be removed after
# generated plugins catch up and the dependency switch has percolated through the plugin
# ecosystem.
var THIS_IS_A_SOFT_DEPRECATION=1;
exit(0);
