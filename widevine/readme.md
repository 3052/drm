# widevine

> Theatricality and deception, powerful agents to the uninitiated. But we are
> initiated, aren’t we, Bruce?
>
> The Dark Knight Rises (2012)

Widevine implementation. first Widevine commit was May 21 2022:

https://github.com/gucio321/mech/commit/9d3dff51

## wvdumper/dumper

install Android Studio [1]. then create Android virtual device:

<dl>
   <dt>abi</dt>
   <dd>x86</dd>
   <dt>api level</dt>
   <dd>24</dd>
   <dt>target</dt>
   <dd>Android 7.0 (Google APIs)</dd>
</dl>

then download Widevine Dumper [2]. Then install:

~~~
pip install -r requirements.txt
~~~

then download Frida server [3], example file:

~~~
frida-server-15.1.17-android-x86.xz
~~~

then start Frida server:

~~~
adb root
adb push frida-server-15.1.17-android-x86 /data/frida-server
adb shell chmod +x /data/frida-server
adb shell /data/frida-server
~~~

then start Android Chrome and visit Shaka Player [4]. click the green play
button. if you receive this prompt:

> bitmovin.com wants to play protected content. Your device’s identity will be
> verified by Google.

click ALLOW. then start dumper:

~~~
$env:PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION = 'python'
python dump_keys.py
~~~

once you see "Hooks completed", go back to Chrome and click the green play
button again. result:

~~~
2022-05-21 02:10:52 PM - Helpers.Scanner - 49 - INFO - Key pairs saved at
key_dumps\Android Emulator 5554/private_keys/4464/2770936375
~~~

1. https://developer.android.com/studio
2. https://github.com/wvdumper/dumper
3. https://github.com/frida/frida/releases
4. https://integration.widevine.com/player

## where did proto file come from?

~~~
media_cas_proxy_sdk\ubuntu\protos\public
~~~

## other tools

- <https://github.com/Jnzzi/4464_L3-CDM>
- https://github.com/FoxRefire/wvg
- https://github.com/hyugogirubato/KeyDive
- https://github.com/search?q=L3+CDM
- https://integration.widevine.com/diagnostics
