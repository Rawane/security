# security
Permet de v�rifier les protocoles et ciphers disponibles sur un serveur pass� en param�tre
si vous avez un proxy,vous pouvez renseigner les informations dans le fichier de properties
application.properties
Vous pouvez �x�cuter la classe main du Projet maven ou org.xoolibeut.security.tls.XoolibeutMainSSL
ou g�n�rer le jar et lancer la commande avec le serveur � v�rifier et le niveau de log
java -jar tsl-check.jar google.fr DEBUG
Exemple de commande :
java org.xoolibeut.security.tls.XoolibeutMainSSL google.fr INFO

R�sultat:

2020-09-07 21:38:58,889 [main] INFO  o.x.security.tls.XoolibeutMainSSL - R�sum� scan ssl/tls 
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
