<?
   $query = $_GET['q']. "#";

   $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
   if ($socket === false) {
   echo "socket_create() failed: reason: " . socket_strerror(socket_last_error()) . "\n";
   } 

   $result = socket_connect($socket, 'ecdsa.org', 50000);
   if ($result === false) {
     echo "socket_connect() failed.\nReason: ($result) " . socket_strerror(socket_last_error($socket)) . "\n";
   } 

   socket_write($socket, $query, strlen($query));

   $buf='ex';
   if (false == ($bytes = socket_recv($socket, $buf, 2048, MSG_WAITALL))) {
     echo "socket_recv() failed; reason: " . socket_strerror(socket_last_error($socket)) . "\n";
   }
   socket_close($socket);
   echo $buf;

?>
