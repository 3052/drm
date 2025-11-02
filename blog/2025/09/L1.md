# L1

~~~
C:\Users\Steven
   media
      L1
         device_client_id_blob
         device_private_key
      L3
         client_id.bin
         private_key.pem
~~~

Remont-aud

Download emmc dump, open in hxd, search for `mstar_secure`

Find one with a weird ending like ending 4-6 bytes in, decrypt with aes ECB and
default mstar key, clean up and that's your keybox

Then search for some variables I've forgotten and store those and that's your
config

Make sure its a mstar soc aswell cause that's easiest

if you cant find it you can use binwalk but its a rust mess and ram hungry

- <https://t.me/DUMP_BIN_FIRMWARETV>
- http://hisenseczech.myqnapcloud.com:8082/share.cgi?ssid=0MmKZDg#0MmKZDg
- http://televid-sib.ru/index.php
- http://televid-sib.ru/index.php?board=1615.0
- https://forum-monitor.net.ru
- https://remont-aud.net/
- https://repairalltv.com/
- https://soft4led.com
- https://staging-hisense.fooprojects.com/downloads/
- https://t.me/flashdumpfile
- https://t.me/flashdumpfile1
- https://www.kazmielecom.tech
- https://www.tecnicenter.org/
