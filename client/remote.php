<?
require_once 'jsonrpcphp/includes/jsonRPCClient.php';
 
echo "<pre>\n";
echo "This page demonstrates the generation of new addresses by a neutralized Electrum wallet.\n\n";
echo "A neutralized wallet does not contain the seed that allows to generate private keys.\nIt contains a master public key that allows to create new addresses.\n\n";
echo "An attacker getting access to the neutralized wallet cannot steal the bitcoins.\n";
echo "The full wallet (with seed) is not stored on the webserver.\n\n";
echo "<form action=\"\" method=\"post\"><input type=\"submit\" name=\"submit\" value=\"Get new address\"/></form> ";

if($_POST['submit']) {
  $daemon = new jsonRPCClient('http://foo:bar@ecdsa.org:8444/');
  try{
  $r = $daemon->getnewaddress();
  if($r) {
      echo '<br/>';
      echo "<a href='bitcoin:$r'>bitcoin:$r</a>\n\n";
    }
  } catch(Exception $e) {
    echo "error: cannot reach wallet daemon";
  }
}
echo "</pre>";
?>
