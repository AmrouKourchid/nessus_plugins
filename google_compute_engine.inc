#TRUSTED 12ed38b27a97b7168c5d513b50394e702fb78cc61b0f2fae039dd3beaaacc14d8bd35c02ea2cf17c2faa5be3a85643636f808bb53c012ad0fbeab43d14c9c4258e946db9524016406a9768f515c183bae6256f4502173abdbbdfa910420aae20bbef5b39cfe90ef2154e2bc73a0c024058c6add9914f3d9ea36d1785d360bae0c2453cf21dfcb22fb62ade0a6f090dcc3dabbbeb894ae33a7f977ac5a8674ececaf03c12b90422eb6626fc0ff2e06e9d596ff4ad7c56221cf1018b89e2caa50a191be1c82a0d27e8fabaedad4c03cf371947749174c2445ac37f5a96f8c404addeb2696f6526e35c2201373eb9ad940c4e3056815eafff907685f648b9fbcf8cc7ed110d1724e8804c33fa95f25c6769d67fbc40b278212803ca74bb82c9d5e7c41c216a0072303903df873c32c0cf9352d71281441736ec5a95ceda68f0025948b72095595b1e62471dbaf407386a1b5b8135296f94b7a30abca3bcab984fad18f8d4c2eafc8e74b296678351b5af3a991e48b026e706171a362d4e9cba361a455bf98a336772a0dc891cf6d463925372d84aacc5dbb6403a4f47dff988d9dc48bd8192e796bcb68b7ca6f019c39b216a67cdb37ca3d03b104474c2466a87d99427bfcd1ee6deca2f39ce92d0a75c22c5da3eb4e28cff0a4fedafdc177b4092bf8a2b2f22f1003ad7e6dc2738a8540d71580bef2652161ff904589b8c023f8e
#TRUST-RSA-SHA256 344920ef398ac66650282c605594dafa2a86992a38d66e8949d4006b6b1c157c62021b307e32c3cb58f168abc27ddaacf6f77ab33db28b48afeea2d4d265f7664a0f3bce871006ae9f8f90dbfd4939ce0b79c3614200bee47c260f0a3b58cca820c8da150bcf5de078be828097f52614150230bf3f6688624eb72286ef68a79418608a15120efb88111ad2aeb70ecde838f8332fd8b0124d0917f8404a632a3dffeac9161fde99a027178c86a5905c073bed048e62c4de719cf271fc1dbc3753dbac3c9990dfdcf83951d1bdd3928cb73f2b9f4854c5aaa6a9ca59eb8fe128a2dda44521d55d23b5cd467086c164aa363e54565318d87ea3e6dd4bc968af4024898e71a2505702384bc8b7ccc4558cbd2b565c6b5bd9ddf31799d2bce7f667cf0775fc66c90800dddd7c963b58f31b6a15f5f2439c2f1de37f3333f84160104b339791df36b877e0295bee9132b7633b5ca39a40b114ac68d15979b97788c2f97fd826c56d028ab09cfb3334d7cb010d835fe55e55a843c8b53d35c1307f4261153d195ed697eedcb8fb929bc99b3b64a63a83413e341f3cdb96c7d14c6740f377a01c02a19059f5fca828d0995c75c5012849602694ef7c110bfe77def752d944ea5a2f9fb0d36c72a84c49b39047ee07cd48b5be57d7af5441396fa263db8c77c6f09ba93ea4bf8a841483da75097f8767ed1b8c5e99ed940b7f6a144737a9
#
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# google_compute_engine.inc
# Revision: 1.2
#

global_var GOOGLE_COMPUTE_ENGINE_API_ROOT, GOOGLE_COMPUTE_ENGINE_API_HOST;
global_var GOOGLE_COMPUTE_ENGINE_API_ITEMS, GOOGLE_COMPUTE_ENGINE_HOST_TAG_BASE;
global_var GOOGLE_COMPUTE_ENGINE_KB_BASE;

# for grabbing IP addresses
global_var GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST;
global_var GOOGLE_COMPUTE_ENGINE_IP;
global_var GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST;
global_var GOOGLE_COMPUTE_ENGINE_EXTERNAL_IP;
global_var GOOGLE_COMPUTE_ENGINE_PROJECT_ID;
global_var GOOGLE_COMPUTE_ENGINE_NUMERIC_PROJECT_ID;

##
# GOOGLE_COMPUTE_ENGINE API Root
##
GOOGLE_COMPUTE_ENGINE_API_ROOT    = "/computeMetadata/v1/instance/";

##
# GOOGLE_COMPUTE_ENGINE API Project ID
##
GOOGLE_COMPUTE_ENGINE_PROJECT_ID  = "/computeMetadata/v1/project/project-id";

##
# GOOGLE_COMPUTE_ENGINE API Numeric Project ID
# NOT USED - Saving for later, just in case!
##
GOOGLE_COMPUTE_ENGINE_NUMERIC_PROJECT_ID = "/computeMetadata/v1/project/numeric-project-id";

##
# GOOGLE_COMPUTE_ENGINE API Host
##
GOOGLE_COMPUTE_ENGINE_API_HOST = "metadata.google.internal";

##
# XML Host Tag base
##
GOOGLE_COMPUTE_ENGINE_HOST_TAG_BASE = "google-compute-engine-instance";

##
# KB Base
##
GOOGLE_COMPUTE_ENGINE_KB_BASE = "Host/Google Compute Engine";

##
# API Items with their validation regular expressions
##
GOOGLE_COMPUTE_ENGINE_API_ITEMS = make_array(
  'name'                , "^[A-Za-z\-0-9.]+$",
  'id'                  , "^[0-9]+$",
  'hostname'            , "^[A-Za-z\-0-9.]+$",
  'zone'                , "[A-Za-z]+\-[A-Za-z0-9]+\-[A-Za-z]+$"
);

# For grabbing IP addresses. X and Y are indexes.
# Internals are at /network-interfaces/X/ip
# Externals are at /network-interfaces/X/access-configs/Y/external-ip
GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST = "network-interfaces/";
GOOGLE_COMPUTE_ENGINE_IP = "ip";
GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST = "access-configs/";
GOOGLE_COMPUTE_ENGINE_EXTERNAL_IP = "external-ip";
