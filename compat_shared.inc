#TRUSTED 980b5d1ac837e256fae917c0ea26a51ce74f6536f4cd3e9b66176c1df2b9602f90a194993abdcfaca22badc10276bc186585772cf4642c1748749fc48945412bbb6ecba9f3dc3a90f49ad520a6d50384d1baeb12f92ebb758c0f897e5b3469e05a534ca27f51a370286ab3330115345b71b33357ee03ffbc3205f1ced3bc29ac2e7ed35d11f1853c7bc9b3a0b7b8f4e7a1347aa847c3c94382bdf34470da823860a230842fc64cc2db1d6dd2b84eba63972cba633d9a4ba418569dbc2fbd37846c6b142d9ba7d12b0ffba3f11608471807c797d7241c33fbcf10dd5f00e19357dd01a06643f5b939850e22c694e61a85e97a0cec9e0cb42b686a39ab4cbe8b89a28a1e4acebaf0fe4015f22b6654a699dbbb3b31a61775762d5095ab6e2ac4890c19dcb57c594163b639f2cfcea19f0ff7dcd464e9562e683657374a15d06919fd284aeed64d35109a1321632624ac81739fc12a7c30e3581b3dc83ccc4ee8dd7299ac357102a145040d16a9751382ef633ae6cce2b9cce3723caa009d1fe95e9cc2de73b7298998f951ab597441eca3d2f2584eca2c1bedf05958f3d23482c63d09646b6a6c6ac666b03baab53aa460ea960d3849764591cf7ce76cbd509f403d1676199dcc2af63bd3314826b792697654412dc5357468387176532d6997c8955f9a37675ac37e4f28b66d007e2f997848e6c41253e0f6c15b96cbcc4a9ad5
#
# (C) Tenable Network Security, Inc.
#
# Redistribution and use in source, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#     This product includes software developed by Tenable Network Security
#
# Revision: 1.4

#pragma static(include)
include("global_settings.static");
include("misc_func.static");
include("audit.static");
include("data_protection.static");
include("obj.static");
#pragma static(include:false)

include("debug.inc");

#
# Backward compatibility functions
#
namespace compat {
  function this_host()
  {
    if (nasl_level() < 80102 || nasl_level() >= 80300) return system::this_host();

    # Workaround for Nessus 8.1.2 - 8.2.x bug where first call returns NULL
    system::this_host();
    return system::this_host();
  }
}
