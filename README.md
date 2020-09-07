# security
Permet de vérifier les protocoles et ciphers disponibles sur un serveur passé en paramètre
si vous avez un proxy,vous pouvez renseigner les informations dans le fichier de properties
application.properties
Vous pouvez éxécuter la classe main du Projet maven ou org.xoolibeut.security.tls.XoolibeutMainSSL
ou générer le jar et lancer la commande avec le serveur à vérifier et le niveau de log
java -jar tsl-check.jar google.fr DEBUG
Exemple de commande :
java org.xoolibeut.security.tls.XoolibeutMainSSL google.fr INFO

Résultat 
 2020-09-07 21:38:58,889 [main] INFO  o.x.security.tls.XoolibeutMainSSL - Résumé scan ssl/tls 
 2020-09-07 21:38:58,889 [main] INFO  o.x.security.tls.XoolibeutMainSSL - 
 2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - Protocol TLSv1
 2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_RSA_WITH_AES_128_CBC_SHA
 2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - 
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - Protocol TLSv1.2
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_RSA_WITH_AES_128_CBC_SHA256
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_RSA_WITH_AES_128_GCM_SHA256
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_RSA_WITH_AES_128_CBC_SHA
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - 
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - Protocol TLSv1.1
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
2020-09-07 21:38:58,890 [main] INFO  o.x.security.tls.XoolibeutMainSSL - TLS_RSA_WITH_AES_128_CBC_SHA
2020-09-07 21:38:58,891 [main] INFO  o.x.security.tls.XoolibeutMainSSL - ............... Fin check ssl
