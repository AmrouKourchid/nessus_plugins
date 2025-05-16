#TRUSTED 8d93185a025b93a7b08f7ba1b898022b37b4172aa783d8e7d90cc8ad66b8ae0090857c09f338c7950ed0629c66e257e4b381626a848f7656eb26cfd211d414e069558d7676dd88df8d508fb9a1b44100fc6abb3862ec6d47bc21df1b5b50b9c2e8472144137337f61a308f909877ac234436456ae97af05d863178811ffc7be6f41b39ebc7575b9bacefe760bf5c863e8b330f751960986491ba3036ca50ef8f3b32446874fbc6302ec600a0a3120226b9eed4b2f107531fecee884a4866d7d77849f671a3c6772f0d4a3ac47ebdeeedb13fc5a60a75bce992e8032ebcd1a13e5838b09368b78d7d86c451ce54c7a598d67f2726dbc60aecee5adca13ea700b69b94e1cfd5952ec3d6e97fee58bb9975055670617a803b19ea002871a5dae5a574990c98e78f50241db347bd15dd638f3dc6a26f0774b57cca5e50c80c6a49215493e1dac2c4c23e240a12830f8a31c04ca3a6ef27e609e74e2f910437bc1986bb73d27beba887bf274b60ce0213b597b541b1a41c8817fbc37d80df109a57008c2dd4d88cfbe9c9e28df304ffd07c9fa4f452b73326a5ff9f55385011267a5f8f6ed280aef2e6a88643a55e866f73cc86df95f68fb9b8407f779c6882c0d15b198879ef20395a3d182eef8b9eb13adfae5cb4cdbc189d5cf9facc2e2dc8cf13861a46223d260d0eed29a8d389547c39338806846c070112de8447cd0241f620
##
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# deprecated_nasl_level.inc
# Revision: 1.3
##

# Prevent further compilation of plugin if Nessus engine is below 8.5.2
namespace __DEPRECATED {
  var env = nasl_environment();
  var product = env['product'];
  # If not an agent and minlevel too low, exit to stop compilation.
  if (product != PRODUCT_WIN_AGENT &&
      product != PRODUCT_UNIX_AGENT &&
      nasl_level() < 80502)
  {
    exit(0, "Either Nessus engine 80502 threshold not met by " + nasl_level() + " or scanner is not an agent.");
  }
}
