---
title: 2025 腾讯游戏安全技术竞赛 安卓客户端方向 初赛
comments: true
date: 2025-03-29 10:47:32
tags:
  - CTF
  - 逆向
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzel5odsv37brbgj4wqkti72rmpf
---

> 封面：[@Bison仓鼠](https://www.bilibili.com/opus/1050917272577638417)

启动游戏后可以明显发现游戏存在加速、自瞄、透视等问题。

首先判断虚幻引擎版本，我们可以直接在`AndroidManifest.xml`中找到UE4.27

![UE_ver](https://img.0a0.moe/od/01tklsjzg26v2fr36wjfgkw5bl25vpvw33)

对所有so文件进行分析。首先利用偷懒的方法，将so文件通过Virustotal计算一下hash查看首次上传时间可以得知，除`libUE4.so`和`libGame.so`都曾经上传过，是标准库，可以不用看

参考文章https://www.cnblogs.com/revercc/p/17641855.html，分别找到libUE4.so中三个核心参数的偏移

```
GWorld 0xAFAC398
GName 0xADF07C0
GUObject 0xAE34A98
```

然后使用[UE4Dumper](https://github.com/revercc/UE4Dumper)对SDK进行提取，再进一步分析

## 异常点1-3：无后座、加速以及加速度

对`libGame.so`进行分析，可以看到该文件对函数使用控制流平坦化混淆，利用IDA插件D-810默认配置即可有效去除进行分析。我们可以留意到有几个异或函数对字符串进行了加密，由于字符串不多这里手动恢复标注即可。

这个so通过`.init_array`调用函数，通过`pthread_create`创建新线程，在`0x1B9C`通过读取`/proc/self/maps`等方法获取`libUE4.so`的基址，然后下面通过基址+偏移计算得到UE4中关键参数的地址

![image-20250329185455154](https://img.0a0.moe/od/01tklsjzdu66g2yz6eurhyt6zuoxayhxyy)

在下面通过遍历Actors中的元素，找到所要的Actor后，通过偏移计算找到对应要修改的参数

![image-20250329190346023](https://img.0a0.moe/od/01tklsjzf7kup2f7cenzg2bvjw57s64ysd)

### 异常点1

根据偏移查找SDK可以得知是开枪时的后坐力，后续通过Frida修改为其他值也可以进一步验证

![image-20250329190400922](https://img.0a0.moe/od/01tklsjzgoo47lbfekyrh22pcpc4n7dfhr)

### 异常点2、3

同理，根据偏移去查找对应的参数，可知是人物的速度和加速度

![image-20250329190618465](https://img.0a0.moe/od/01tklsjzhi5tczyvpnd5gyibll7e56gx74)

### 修复

这里选择将这三个地方的`STR`赋值汇编NOP掉，阻止其修改，应用patch，使用MT管理器替换so将apk重新打包签名，即可修复

![image-20250329191133745](https://img.0a0.moe/od/01tklsjzffnyq2zikjerd2y3azf6saggny)

![image-20250329191152965](https://img.0a0.moe/od/01tklsjzcvoygodescfnfii6qlum7kw6eb)

## 异常点4：自瞄

在游戏内开枪，可以发现在开枪时视角/枪口被强制面向其中一个cube。对SDK进行分析，通过Frida Hook进一步确认，发现`Controller.Actor.Object`内的`ControlRotation`决定视角/枪口，可以修改这个值来实现自瞄

```javascript
class Rotator {
    constructor(Pitch, Yaw, Roll) {
        this.Pitch = Pitch;
        this.Yaw = Yaw;
        this.Roll = Roll;
    }
    toString() {
        return `(${this.Pitch}, ${this.Yaw}, ${this.Roll})`;
    }
}

function dumpRotator(rotatorAddr){
    const values = Memory.readByteArray(rotatorAddr, 3 * 4);
    const rot = new Rotator(
        new Float32Array(values, 0, 1)[0], 
        new Float32Array(values, 4, 1)[0], 
        new Float32Array(values, 8, 1)[0] 
    );
    console.log("dump rot", rot);
    return rot;
}

function getControlRotation(actorAddr){
    var data_addr = ptr(actorAddr).add(0x288);
    var rot = dumpRotator(data_addr);
    return rot;
}

function writeControlRotation(actorAddr, a, b, c){
    ptr(actorAddr).add(0x288).writeFloat(a);
    ptr(actorAddr).add(0x288+4).writeFloat(b);
    ptr(actorAddr).add(0x288+8).writeFloat(c);
}

```

![image-20250329191835258](https://img.0a0.moe/od/01tklsjzeqg3rf6detibayv4gly7p6vxr5)

因此可以对Actor列表里的`PlayerController+0x288`的位置下一个写硬件断点，在其被修改时栈回溯找到修改函数。

![屏幕截图 2025-03-29 104825](https://img.0a0.moe/od/01tklsjzfc5fs7dvkux5glytzslzwfnhrq)

使用[stackplz](https://github.com/SeeFlowerX/stackplz)断点，可以发现正常移动视角时，堆栈情况如hit_count:4，而开枪时则hit_count:3的情况，对比两种情况，因为两种情况都要进入#00所在的函数，因此不好patch。通过frida replace置空#01所在函数，可以发现无法正常开枪，因此该函数与开枪有关系，在这之前也不能动。因此只能对#01所在的函数跳转`BLR`patch成`NOP`，阻止其修改ControlRotation，即可修复。

![image-20250329193238453](https://img.0a0.moe/od/01tklsjzdrhvg635zeijczsghik3ptjvaz)

## 异常点5：子弹乱飞

在修复自瞄后开枪会发现，子弹并不朝着准星瞄准的方向发射，在查阅相关资料后，得知子弹发射时会通过GunOffset、Location和Rotation等参数计算出发射位置及方向。使用Frida对相关参数进行获取可发现GunOffset这一参数被设置为(100, 0, 10)，且通过硬件断点确定该参数在开枪时会被读取。将其修改为(0, 0, 20)后，子弹乱飞情况有所缓解，但未能彻底解决，测试在Yaw为90，270时（即人物侧对地面文字）影响较大，0，180，360时（即人物正对地面文字）影响较小。

```javascript
function getGunOffset(actorAddr){
    var data_addr = ptr(actorAddr).add(0x500);
    dumpVector(data_addr);
}

function writeGunOffset(actorAddr, x, y, z){
    ptr(actorAddr).add(0x500).writeFloat(x);
    ptr(actorAddr).add(0x500+4).writeFloat(y);
    ptr(actorAddr).add(0x500+8).writeFloat(z);
}

writeGunOffset(actorAddrs["FirstPersonCharacter_C"], 0, 0, 20);
```

![image-20250329193930047](https://img.0a0.moe/od/01tklsjzamori4kxlovjhkmacgrm7hkguv)

在射击函数中，也就是前面自瞄修复的下面，可以看到0x670FBAC的函数中有两个rand函数。将其patch成固定值后，此处我patch成0x7fffff(0xffffff/2)后运行发现小球能够以相对稳定的角度射出，说明此处随机数确实与前面小球左右横跳的情况有关

![image-20250330005044597](https://img.0a0.moe/od/01tklsjzc6tv2xmstdrbc22zggwwfu6stk)

但仍未弄清楚此处计算结果与ControlRotation还会如何运算。在`0x8D2ED80`、`0x8D2E214`的函数里面，可见`ActorSpawning`的字符串以及对`UObject`列表等进行修改，此处应该生成了Projectile。本人猜想是需要在这附近对生成子弹的角度修改为ControlRotation，使小球恢复向玩家前方射出，参考UE官方示例代码https://dev.epicgames.com/documentation/zh-cn/unreal-engine/3---implementing-projectiles?application_version=4.27#%E5%AE%9E%E7%8E%B0%E5%8F%91%E5%B0%84%E5%87%BD%E6%95%B0

![image-20250330112923633](https://img.0a0.moe/od/01tklsjzb46qukffzmsnf3bq3sxqgcp2vg)

对应一下

![image-20250330120524114](https://img.0a0.moe/od/01tklsjzdnhs6z7og3hzhkgbeoeanxhbxo)

刚好符合SpawnActor的构造，1个指针+4个参数，使用脚本hook一下第3个参数

![image-20250330120647854](https://img.0a0.moe/od/01tklsjzg77dqzk7yy3zhifuqrkmpwc3wx)

上面是传入该函数的Rotation，下面是PlayerController的Rotation，可见刚好写反（此处调试时已把rand patch掉），把传参改回来就行

```javascript
    var func_addr = moduleBase.add(0x8D2ED80)
    Interceptor.attach(func_addr, {
        onEnter: function (args) {
            dumpRotator(ptr(args[3]));
            var playerRotation = getControlRotation(actorAddrs["PlayerController"]);
            ptr(args[3]).writeFloat(playerRotation.Pitch);
            ptr(args[3]).add(4).writeFloat(playerRotation.Yaw);

        },
        onLeave: function (retval) {
        }
    });
```

此时子弹即可正常向前方射出，但是准心偏下，这个就需要慢慢调参解决

## 异常点6：透视

可以看到FirstPersonCharacter_C和ThirdPersonCharacter都被渲染成红色，可以猜测二者被应用同一修改

网上查找过相关资料，透视可通过渲染自定义深度实现，Frida测试过这里并没有开启该参数

```javascript
function getRenderCustomDepth(actorAddr){
    var value = ptr(actorAddr).add(0x212).readU8();
    var bitValue = (value >> 3) & 1;
    return bitValue;
}

function getAllRenderCustomDepth(){
    const actors = getActorsAddr();
    for (const actorName in actors) {
        if (actors.hasOwnProperty(actorName)) {
            const actorAddr = actors[actorName];
            try {
                var value = getRenderCustomDepth(actorAddr);
                console.log(`RenderCustomDepth of ${actorName} at ${actorAddr}: ${value}`);
            } catch (e) {
                console.error(`Failed to get RenderCustomDepth of ${actorName} at ${actorAddr}: ${e}`);
            }
        }
    }
}
```

由于对UE4渲染这方面实在不熟悉，不清楚该功能如何实现。猜想可能是从源码上修改了Character.Pawn.Actor.Object的深度，使其渲染在其他Actor的顶层，同时使其渲染成红色。



## 相关Frida脚本

```javascript
var moduleBase;
var GWorld;
var GWorld_Ptr_Offset = 0xAFAC398;
var GName;
var GName_Offset = 0xADF07C0;
var GObjects;
var GObjects_Offset = 0xAE34A98;
var actorAddrs

var offset_UObject_InternalIndex = 0xC;
var offset_UObject_ClassPrivate = 0x10;
var offset_UObject_FNameIndex = 0x18;
var offset_UObject_OuterPrivate = 0x20;

var GUObject = {
    getClass: function (obj) {
        return ptr(obj).add(offset_UObject_ClassPrivate).readPointer();
    },
    getNameId: function (obj) {
        try {
            return ptr(obj).add(offset_UObject_FNameIndex).readU32();
        }
        catch (e) {
            return 0;
        }
    },
    getName: function(obj) {
        if (this.isValid(obj)){
            return getFNameFromID(this.getNameId(obj));
        } else {
            return "None";
        }
    },
    getClassName: function(obj) {
        if (this.isValid(obj)) {
            var classPrivate = this.getClass(obj);
            return this.getName(classPrivate);
        } else {
            return "None";
        }
    },
    isValid: function(obj) {
        return (ptr(obj) > 0 && this.getNameId(obj) > 0 && this.getClass(obj) > 0);
    }
}

function getFNameFromID(index) {
    var FNameStride = 0x2
    var offset_GName_FNamePool = 0x30;
    var offset_FNamePool_Blocks = 0x10;

    var offset_FNameEntry_Info = 0;
    var FNameEntry_LenBit = 6;
    var offset_FNameEntry_String = 0x2;
 
    var Block = index >> 16;
    var Offset = index & 65535;

    var FNamePool = GName.add(offset_GName_FNamePool);
    var NamePoolChunk = FNamePool.add(offset_FNamePool_Blocks + Block * 8).readPointer();
    var FNameEntry = NamePoolChunk.add(FNameStride * Offset);

    try {
        if (offset_FNameEntry_Info !== 0) {
            var FNameEntryHeader = FNameEntry.add(offset_FNameEntry_Info).readU16();    
        } else {
            var FNameEntryHeader = FNameEntry.readU16();
        }
    } catch(e) {
        return "";
    }

    var str_addr = FNameEntry.add(offset_FNameEntry_String);
    var str_length = FNameEntryHeader >> FNameEntry_LenBit;
    var wide = FNameEntryHeader & 1;
    if (wide) return "widestr";
 
    if (str_length > 0 && str_length < 250) {
        var str = str_addr.readUtf8String(str_length);
        return str;
    } else {
        return "None";
    }
}

function set(modulename) {
    moduleBase = Module.findBaseAddress(modulename);
    GWorld = moduleBase.add(GWorld_Ptr_Offset).readPointer();
    GName = moduleBase.add(GName_Offset);
    GObjects = moduleBase.add(GObjects_Offset);
}

function getActorsAddr(){
    var Level_Offset = 0x30
    var Actors_Offset = 0x98
 
    var Level = GWorld.add(Level_Offset).readPointer()
    var Actors = Level.add(Actors_Offset).readPointer()
    var Actors_Num = Level.add(Actors_Offset).add(8).readU32()
    var actorsAddr = {};
    for(var index = 0; index < Actors_Num; index++){
        var actor_addr = Actors.add(index * 8).readPointer()
        var actorName = GUObject.getName(actor_addr)
        actorsAddr[actorName] = actor_addr;    
    }
    return actorsAddr;
}

class Vector {
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    toString() {
        return `(${this.x}, ${this.y}, ${this.z})`;
    }
}

class Rotator {
    constructor(Pitch, Yaw, Roll) {
        this.Pitch = Pitch;
        this.Yaw = Yaw;
        this.Roll = Roll;
    }
    toString() {
        return `(${this.Pitch}, ${this.Yaw}, ${this.Roll})`;
    }
}

function dumpVector(vectorAddr){
    const values = Memory.readByteArray(vectorAddr, 3 * 4);
    const vec = new Vector(
        new Float32Array(values, 0, 1)[0], 
        new Float32Array(values, 4, 1)[0], 
        new Float32Array(values, 8, 1)[0] 
    );
    console.log("dump vec", vec);
    return vec;
}

function dumpRotator(rotatorAddr){
    const values = Memory.readByteArray(rotatorAddr, 3 * 4);
    const rot = new Rotator(
        new Float32Array(values, 0, 1)[0], 
        new Float32Array(values, 4, 1)[0], 
        new Float32Array(values, 8, 1)[0] 
    );
    console.log("dump rot", rot);
    return rot;
}

function getActorLocation(actorAddr){
    var functionAddr = moduleBase.add(0x92e16b4);
    var getActorLocationFunc = new NativeFunction(functionAddr, 'void', ['pointer', 'pointer', 'pointer']);
    var location = Memory.alloc(0x100);
    try{
        getActorLocationFunc(ptr(actorAddr), location, location);
        dumpVector(location);
        return location;
    }
    catch(e){
    }
}

function getActorRotation(actorAddr){
    var functionAddr = moduleBase.add(0x937BB14);
    var getActorRotationFunc = new NativeFunction(functionAddr, 'void', ['pointer', 'pointer', 'pointer']);
    var rotation = Memory.alloc(0x100);
    try{
        getActorRotationFunc(ptr(actorAddr), rotation, rotation);
        dumpRotator(rotation);
        return rotation;
    }
    catch(e){
    }
}

// function getVector(actorAddr){
//     var data_addr = ptr(actorAddr).add(0x500);
//     dumpVector(data_addr);
// }

// function writeVector(actorAddr, x, y, z){
//     ptr(actorAddr).add(0x500).writeFloat(x);
//     ptr(actorAddr).add(0x500+4).writeFloat(y);
//     ptr(actorAddr).add(0x500+8).writeFloat(z);
// }


function getGunOffset(actorAddr){
    var data_addr = ptr(actorAddr).add(0x500);
    dumpVector(data_addr);
}

function writeGunOffset(actorAddr, x, y, z){
    ptr(actorAddr).add(0x500).writeFloat(x);
    ptr(actorAddr).add(0x500+4).writeFloat(y);
    ptr(actorAddr).add(0x500+8).writeFloat(z);
}

function getControlRotation(actorAddr){
    var data_addr = ptr(actorAddr).add(0x288);
    var rot = dumpRotator(data_addr);
    return rot;
}

function writeControlRotation(actorAddr, a, b, c){
    ptr(actorAddr).add(0x288).writeFloat(a);
    ptr(actorAddr).add(0x288+4).writeFloat(b);
    ptr(actorAddr).add(0x288+8).writeFloat(c);
}


// function getFloat(actorAddr){
//     var data_addr = ptr(actorAddr).add(0x1a0);
//     const values = Memory.readByteArray(data_addr, 4);
//     console.log(new Float32Array(values, 0, 1)[0]);
// }

// function writeFloat(actorAddr, value){
//     ptr(actorAddr).add(0x52c).writeFloat(value);
// }


function getProjectil(){
    // 判断actorAddrs是否有FirstPersonProjectile_C
    actorAddrs = getActorsAddr();
    if (actorAddrs.hasOwnProperty("FirstPersonProjectile_C")) {
        var actorAddr = actorAddrs["FirstPersonProjectile_C"];
        var projectileMovement_addr = ptr(actorAddr).add(0x228).readPointer();
        console.log(projectileMovement_addr.add(0xec).readFloat());
    }

}


function setRenderCustomDepth(actorAddr, bEnabled){
    var functionAddr = moduleBase.add(0x8AB9DE8);
    var setRenderCustomDepthFunc = new NativeFunction(functionAddr, 'void', ['pointer', 'char']);
    setRenderCustomDepthFunc(ptr(actorAddr), bEnabled);
}

function applyCustomDepthToAllActors(bEnabled) {
    const actors = getActorsAddr(); // 获取所有Actor地址
    for (const actorName in actors) {
        if (actors.hasOwnProperty(actorName)) {
            const actorAddr = actors[actorName];
            try {
                setRenderCustomDepth(actorAddr, bEnabled); // 调用函数设置CustomDepth
                console.log(`Applied CustomDepth to ${actorName} at ${actorAddr}`);
            } catch (e) {
                console.error(`Failed to apply CustomDepth to ${actorName} at ${actorAddr}: ${e}`);
            }
        }
    }
}

function setCustomDepthStencilValue(actorAddr, value){
    var functionAddr = moduleBase.add(0x8AB9E0C);
    var setCustomDepthStencilValueFunc = new NativeFunction(functionAddr, 'void', ['pointer', 'int']);
    setCustomDepthStencilValueFunc(ptr(actorAddr), value);
}


function getRenderCustomDepth(actorAddr){
    var value = ptr(actorAddr).add(0x212).readU8();
    var bitValue = (value >> 3) & 1;
    return bitValue;
}

function getAllRenderCustomDepth(){
    const actors = getActorsAddr();
    for (const actorName in actors) {
        if (actors.hasOwnProperty(actorName)) {
            const actorAddr = actors[actorName];
            try {
                var value = getRenderCustomDepth(actorAddr);
                console.log(`RenderCustomDepth of ${actorName} at ${actorAddr}: ${value}`);
            } catch (e) {
                console.error(`Failed to get RenderCustomDepth of ${actorName} at ${actorAddr}: ${e}`);
            }
        }
    }
}


function main(){
    Java.perform(function(){
        set("libUE4.so");
        actorAddrs = getActorsAddr();
        writeGunOffset(actorAddrs["FirstPersonCharacter_C"], 0, 0, 20);
    });

    var func_addr = moduleBase.add(0x8D2ED80)
    Interceptor.attach(func_addr, {
        onEnter: function (args) {
            dumpRotator(ptr(args[3]));
            var playerRotation = getControlRotation(actorAddrs["PlayerController"]);
            ptr(args[3]).writeFloat(playerRotation.Pitch);
            ptr(args[3]).add(4).writeFloat(playerRotation.Yaw);

        },
        onLeave: function (retval) {
        }
    });

}

setImmediate(main);
```

