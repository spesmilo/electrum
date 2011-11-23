<?

 function do_query($q){
   $q .= "#";

   $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
   if ($socket === false) {
   echo "socket_create() failed: reason: " . socket_strerror(socket_last_error()) . "\n";
   } 

   $result = socket_connect($socket, 'ecdsa.org', 50000);
   if ($result === false) {
     echo "socket_connect() failed.\nReason: ($result) " . socket_strerror(socket_last_error($socket)) . "\n";
   } 
   socket_write($socket, $q, strlen($q));
   $buf='ex';
   if (false == ($bytes = socket_recv($socket, $buf, 2048, MSG_WAITALL))) {
     echo "socket_recv() failed; reason: " . socket_strerror(socket_last_error($socket)) . "\n";
   }
   socket_close($socket);
   return $buf;
 }

   $pass = '';

   $query = $_POST['q'];
   if( !$query ) {
   echo "Welcome to <a href=\"http://ecdsa.org/electrum/\">Electrum</a><br/>";
   echo "This server uses ports 80 (http), 443 (https) and 50000 (raw)<br/>";
   echo "Port 50000 is recommended for efficiency.<br/><br/>";

   echo "Server status:<br/>";
   echo "Number of blocks: ". do_query( "('b','')" ) ."<br/>";
   echo "Current load: ". do_query( "('load','$pass')" ) ."<br/><br/>";

   echo "List of active servers:<br/>\n";
   $str = do_query( "('peers','')" );
// preg_match_all("/\('(.*?)', '(\d+\.\d+\.\d+\.\d+)'\)/",$str,$matches,PREG_SET_ORDER);
   preg_match_all("/\('(.*?)', '(.*?)'\)/", $str, $matches, PREG_SET_ORDER);
   echo "<ul>";
   foreach( $matches as $m){
     echo "<li><a href=\"http://" . $m[2] . "/electrum.php\">" . $m[2]."</a> <small>[".$m[1]."]</small></li>";
   } 
   echo "</ul>";

   } else {
     $buf = do_query($query);
     echo $buf;
   }    
?>
