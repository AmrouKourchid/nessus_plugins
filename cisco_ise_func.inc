#TRUSTED 9c8815bc03db37c0bb2bce1ae41f06be45d3b5015a9e1153a61f7083a4030cb77ecf145d85d8e53a1ddc959559ebc0ec9fd9480b2f5779b160e6c16d17647ffbcce391003b8a438a48076d8aec5857379783e4786654b1993d10ed73be96d825792479087aa91900023d98c3bd6568c50ccf701b8b0916eae5cbf7969d512fbf530b784c5798fca5a6be0055e327a103278601b8cefaebdaf6d5b0041f748c5ed3786e57157b35fa27883b2eab41c70abeab264a781ac4225d82a6a4893b50d35dc0658de2612850052b4d16c14b9af6f20a298a7e71081cea9e340a8c7ceb178479a159ffe35db43bac29b14169e0bc0f4becf930901903ea7ff151994cec7d5dc2cc11d76a50ffda60cab6beda64a126a8833423d8b0002ae1fdce97298f0b724a63b4248fa2cd438194283aa9eccae19a1190263f5ada27ee0052a9f34133169839c8c82a043862cc00ecb603665f7007fb8d82ea152d5aa7458214bc2fe0f408fde335a269849a54ec136cd42651dab5f7787fcab9311d6c7c1ea427b51dfdfb4f7846d261f0e0d607e841c1c641c3591a2ebf8c4f2ab222a2f8deab655c314bd61d0bdc10bf5b538036f686f6b74d4d17f3ec9c86c57153b7c85d06aa1e65ec444fbed6fe436132169d99af3fb790340010f6bde0b5c4116d44d383fb106b3be88164ad04efa1530b75d03ddd821c75b45520eee5611a3bad0c072b6587
#TRUST-RSA-SHA256 44bf6ec9cdee3f21b390b0adca0b599793d7f22b477c2fe802a73570e4de2a8358d814e29ac30eca967e3aff6591cfb059e990290d20027d8cbe0248a91ca720600fe1e1760760735f4e49de86f4bbbfed63e61e897250b665d2a5b10bfd312fdf408069e2ebf60da673848eb56f6c0428c74f71a26755d8366a571109582c0d3d883184d76f1eb82124200975ab7ac843626401c89ecd04305ef9fa2b5ee5f7e2740b5e1c52e012a44fda68dc41e9c13bbe2c49023d031c5471688c4a7f93447e3675e4e1ca03c216b21e67213d5a8ad5fe16d9c371f812ed4e6cb2717582d4821229768b7d724a48b154f5b62f3d8849d01f961d939b8eba580d19776ee1de87e145587848f3f64272a60638660eb11eb31d231a30c8bbf86ea289554a676e69331eabaabc9a29402c45ec94d8f76761bb4ea281a2a79cdc66f2da40f44c0544269a57f47e7a764a4c03b4e1e2cd622c63d2f6e35250b84f342d8806484414090fcf48d4bb60c768bd8df86e3ea68a1b97d93ccee643184ed2ec95240c89fa4956c826cb10682cf3d73c23ec4769a920e2d0947396ccf4f9bbe92f80531f1fd009a2502a4a1cd186d11bf166e41006efbd895ec8fc542748836654c78a2343451e0b63d3cedf5ae3b3eb91a9a80abee1a136ff439d2fb42dd8f6ad7aa853ed7dd2eae26b9c22587920261279f20e163f3f3cb67867397a164e26cfb686879e
##
# (C) Tenable, Inc.
##
include('compat_shared.inc');
include('cisco_func.inc');

function strip_fourth_segment(product_info)
{
  if (empty_or_null(product_info.display_version))
    product_info.display_version = product_info.version;

  var version_parts = split(product_info.version, sep:'.', keep:FALSE);
  if (len(version_parts) == 4)
  {
    product_info.version = version_parts[0] + '.' + version_parts[1] + '.' + version_parts[2];
  }

  return product_info;
}

function get_required_patch(vuln_ranges, version) 
{
  foreach var vuln_range (vuln_ranges) 
  {
    if (cisco_gen_ver_compare(a:version, b:vuln_range['min_ver']) >= 0 && cisco_gen_ver_compare(a:version, b:vuln_range['fix_ver']) <= 0)
      return vuln_range['required_patch'];
  }
  return NULL;
}

function get_largest_patch(patches) 
{
  var largest = patches[0];
  for (var i = 1; i < max_index(patches); i++) 
  {
    if (patches[i] > largest)
      largest = patches[i];
  }
  return largest;
}
