#TRUSTED 8ce7114dbef05c34c41901d136a2fa3e060bb10c0516a8d3be732af968c11c14b1873fc72af423da3fafe5dbc37b82e5ad6ae0fc70f7778cb410aaf2b185786a10e0de815d09058fac98e74466397892fbb2cc2a969e85f0c3a0e2f13ca9382054aaeec5d2672e16ea48e442a46378c1beb0377f00a3594283834a29bcf96e3c78a68824d1976a6f411094e170e9f2f04cb382a0966a4932bc82f05b97a1443ab0377693f9ec98dc62bec0047b89b5849820a47eae3ed316850cdd14f21e2f33d771ff197f7047fe5504be307b30184e83b73a0ff1f33fb829cc87126c6584f5576887c95413d696b1c3376fa12994b6e48d4c40ce20ce902a0391ee4aef9b499824dfa7d7d8b879e377fddcba2195bb560a705c6e98ae75f0d7c62cc0f287372b7ffe4df8ad6b31de9717962c1f7cabc66d2eb531ed177050db236b30fe203e24f5c2686a5bad4dddc2d446467cadd034fd1e40c651d43d3c64bdb3239fb02dc6c39ee720347d59b69b442c52a07ac5ba8149dec00bdd27cdfa172d8b776ea8b13c2ba749c01c1a3585da6777a9d481ac29a31c0fae475fb75d41b098c29f60ef0b525b6a5e05f191ba12abd22bd53f219a92b2f5d23613dfbef1eaa0cf7392ba4833b69e0a3ea36a4a86cce022ed2a0469c1758157f72db36ff10403f9801ffa01d1653d56bab81e868ac32a74de56a6450f30864dc851b99bf13bd662c58b
#TRUST-RSA-SHA256 14ef6dceb34adc3f0423dc1dccf703a212e49648fa2ebb69d0f9db9c5ee0ad64aa3756587b1a8396636fa9058dbdbf0344f406523bc3205523b21e4b1e1ca7bb43ff520b40a625d232539b0fb3e419dba3944e1d43719dd6bd96831c073b0be1272c1492bff50797b81053511da30de7fac05573055c5cbffd3dc9448eb66870836859554c08324e0f7bd3d08fb9e97b6adab9bfd78886589b43ee4e016225deccf0a7855ac92dcf10f543f2ec5e1da3122019734cfcd31ed85703d3fddd8209a1dd31fb3704cd9411bdb90027cbd94e1bdda6397ce9101043f085a4f06b73cd90e4056be192cdb5cc8446e74a9f9a02aedd4aa36ef26a84bae0463f94d9216d7feeb2c9be83a57d60d85a5eb7105797be84b71389ceab94c7cae5c79a9a81bce21998a2dde4f965b46aefed1909f67d620d8cc769f816a86eee46474fd9d68946890728fd0d66cf3a3e2580a1516181bb1b6c2f30605dd311901d50463a7e6999353654192ae4585d19ddf84f54171cf678b55c974feadfd867b1041b724e5d1d989784344af4ca591cbe1739149247695a4c418ae40a190fbfbc6a6d89cfca3d72e77d94c1ae6fd57ccc0169953d73be4b621d6b39863db8d4a3dac860222402d7a14a7765633ae94abd94ac973067d39832026015c6286a9624d986a3129c35099f721514decb97605ce626d2230fd6b0da8db53622e110ec56c7f13d60dd
###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# Revision: 1.2
#
###

include('compat_shared.inc');


##
# Convert hex string to escaped '\x' format.
#
# @param [hex_str:str]             hex string to escape (e.g. "00b8")
# @param [reverse_byte_order:bool] reverse the byte order
#
# @return string of the hex string (e.g. "\x00\xb8")
##
function convert_hex_str_to_escaped_format(hex_str, reverse_byte_order)
{
  var hex_list = [];
  var byte;

  if (empty_or_null(reverse_byte_order))
    reverse_byte_order = false;

  var hex_str_len = len(hex_str)-1;
  for (var i=0; i<hex_str_len+1; i++)
  {
    byte = hex_str[i];

    if (reverse_byte_order)
      hex_list[hex_str_len-i] = hexstr(byte);
    else
      hex_list[i] = hexstr(byte);
  }

  var escaped_hex = '\\x' + join(hex_list, sep:'\\x');

  return escaped_hex;
}
