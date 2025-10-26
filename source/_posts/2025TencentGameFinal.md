---
title: tencent2
comments: true
date: 2025-04-11 16:22:31
tags:
  - CTF
  - 逆向
categories:
  - 技术
---

分析游戏，跟初赛同理可得UE4.27.2，查找相关参数

```
GWorld AFAC398
GName ADF07C0
GUObjectArray AE34A98
```

利用ue4dumper dump出SDK以备查询

## 外挂分析

### ACEInject模块

该模块通过`customize.sh`复制注入的so到游戏目录下

```sh
mkdir -p "/data/data/com.ACE2025.Game/"
unzip -o "$ZIPFILE" "libGame.so" -d "/data/data/com.ACE2025.Game/"
set_perm_recursive "$MODPATH" 0 0 0755 0644
```

在模块启用时，通过`zygisk/arm64-v8a.so`里的`zygisk_module_entry`函数，执行`off_1CE8`列表里的函数，先是在`sub_B7C-->sub_9FC`判断了游戏程序`com.ACE2025.Game`，然后在`sub_BB0-->sub_A68`通过`dloen`加载前面解压出来的`libGame.so`

接着一样跟初赛时加载so的方法类似，在`.init_array`中调用`pthread_create`创建一个新线程对游戏内存进行修改。跟进创建新线程的函数，可以看到`sub_12D8`获取了`libUE4.so`的基址，然后在baseAddr+0x6711AC4的位置，先是通过`sub_1618`对该地址4字节修改为`rwx`，然后将位于该地址的`08 14 A8 52`改为`08 59 A8 52`，即汇编的`MOV W8, #5.0`变成`MOV W8, #100.0`

![image-20250411172535879](https://img.0a0.moe/od/01tklsjzhkgicbjn2eurbj5bqelhp6dcdq)

![image-20250411172548264](https://img.0a0.moe/od/01tklsjzhojevoefjl3jfkqtqqoi7ii4x4)

可以看到球体半径参数被修改

然后在这个模块里so文件的最下面，还有一系列anti操作，包括检测是否是子线程、是否被调试、是否存在常见调试端口、是否有常见frida特征、fopen、dlsym、dlopen是否被hook等，如果匹配上就让程序退出。

### cheat程序

程序在start中通过libc_init调用sub_241D90，里面通过am start启动游戏activity后等待进入sub_241BF0。进入后在一串函数中可以发现imgui的特征

![image-20250411191602526](https://img.0a0.moe/od/01tklsjzghhhdvhwqmorbiw43rnlulk3i2)

在sub_247504可以看到绘制的整个外挂ui。在这里面的“初始化辅助”下面的sub_243414里面，我们可以看到获取了libUE4.so的基址。还是在这个函数里，sub_242C5C函数传入了"MyProjectCharacter"，查看函数内部逻辑，以及进一步查找这个函数的引用，可以发现这个函数在其他地方传入了"TP_ThirdPersonCharacter"，因此可以分析推测该函数获取了相应Actor的地址。



我们可以看到函数内部多处调用了syscall，其中第一个参数都是dword_2B64B8。dword_2B64B8=0x10E=270，没有写操作，查询ARM64 syscall table可知是process_vm_readv

|  NR  |   syscall name   |                          references                          |  %x8  | arg0 (%x0) |        arg1 (%x1)        |      arg2 (%x2)       |        arg3 (%x3)        |      arg4 (%x4)       |     arg5 (%x5)      |
| :--: | :--------------: | :----------------------------------------------------------: | :---: | :--------: | :----------------------: | :-------------------: | :----------------------: | :-------------------: | :-----------------: |
| 270  | process_vm_readv | [man/](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html) [cs/](https://source.chromium.org/search?ss=chromiumos&q=SYSCALL_DEFINE.*process_vm_readv) | 0x10e | pid_t pid  | const struct iovec *lvec | unsigned long liovcnt | const struct iovec *rvec | unsigned long riovcnt | unsigned long flags |

- arg1 是本地接收缓冲区指针；
- arg3 是远程内存地址描述；
- 该 syscall 会将远程进程内存数据拷贝到本地。

因此可以得知，该程序主要是通过syscall读取玩家和npc(ThirdPersonCharacter)的坐标位置，通过运算得到对应的屏幕位置，使用imgui渲染出来，该部分主要为sub_24423C的函数。可以发现获取了"head"、"neck"、"spine"、"upperarm"、"lowerarm"、"hand"、"thigh"、"calf"、"foot"等的数据，用于获取透视时的人物骨骼

通过hook验证，自瞄开关函数旁边传入的`byte_2B65EC`即控制是否开启自瞄的变量，查找该变量的引用，配合硬件断点栈回溯，可以确定0x2442c0为绘制自瞄范围，0x2438d8这里涉及自瞄逻辑。跟进后可通过patch和函数逻辑分析确定sub_24E09C涉及自瞄。可以通过patch后的现象发现与触摸的输入相关，猜测实现为模拟触摸输入

hook相关参数，可以发现如果一直拉枪，前两个参数由一个固定的值逐渐减小直到其中一个为0，再重新开始。如果偏移较远，自瞄时这两个参数减小速度较快

```javascript
var base_addr = Module.findBaseAddress("cheat")
var func_addr = base_addr.add(0x24e09c)
Interceptor.attach(func_addr, {
        onEnter: function (args) {
            console.log(args[0], args[1], args[2])
        },
        onLeave: function (retval) {
        }
});
```

## 检测外挂

### ACEInject模块

#### 检测1

可以直接通过检测对应位置的值是否被修改来判断。此处因为已知固定位置被修改，可以只读取固定位置判断即可。对于不知道修改位置的，可以对代码段进行crc32校验，判断程序是否被修改

```c++
void check_libUE4_modified(void* base) {
    sleep(5);
    uintptr_t offset = 0x6711AC4;
    uintptr_t target = (uintptr_t)base + offset;
    uint32_t value = *(uint32_t*)target;
    LOGI(">>> [check_libUE4_modified] Value at offset: %u", value);
    if (value != 1386746888) {
        LOGW(">>> [check_libUE4_modified] Value has been modified!");
        FILE* log_file = fopen(LOGPATH, "a");
        if (log_file) {
            fprintf(log_file, "[!] Detected modification in libUE4.so\n");
            fclose(log_file);
        }
    }
}

```

#### 检测2

利用/proc/self/maps检测对应代码段权限是否被修改，出现可写且可执行的段很明显不正常

```c++
void check_libUE4_rwxp_segment() {
    sleep(4);
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libUE4.so")) {
            if (strstr(line, "rwxp")) {
                fclose(fp);
                LOGW(">>> [check_libUE4_rwxp_segment] Found rwxp segment: %s", line);
                FILE* log_file = fopen(LOGPATH, "a");
                if (log_file) {
                    fprintf(log_file, "[!] Detected segment permission was modified: %s\n", line);
                    fclose(log_file);
                }
                return;
            }
        }
    }
    fclose(fp);
}
```

#### 检测3

利用/proc/self/maps检测是否出现了不应该出现的可疑so文件，实际操作中可以对用到的so和系统运行时用到的so拉个白名单

```c++
void check_libGame_injected() {
    sleep(3);
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libGame.so")) {
            fclose(fp);
            LOGW(">>> [check_libGame_injected] Found libGame.so: %s", line);
            FILE* log_file = fopen(LOGPATH, "a");
            if (log_file) {
                fprintf(log_file, "[!] Detected libGame.so injection: %s\n", line);
                fclose(log_file);
            }
            return;
        }
    }
    fclose(fp);
}
```

#### 检测4

由于模块在应用data目录释放了libGame.so文件，因此可以对应用目录建立白名单机制，检查是否存在陌生可疑文件

```c++
void scan_directory_for_libGame(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat st{};
        if (stat(fullpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                scan_directory_for_libGame(fullpath);  // 递归子目录
            } else if (S_ISREG(st.st_mode)) {
                if (strcmp(entry->d_name, "libGame.so") == 0) {
                    LOGW(">>> [scan_directory_for_libGame] Found suspicious file: %s", fullpath);
                    FILE* log_file = fopen(LOGPATH, "a");
                    if (log_file) {
                        fprintf(log_file, "[!] Detected suspicious file: %s\n", fullpath);
                        fclose(log_file);
                    }
                }
            }
        }
    }
    closedir(dir);
}
```

#### 检测5

这个模块由于采用了zygisk注入，因此可以通过检测zygisk注入痕迹来判断。参考https://blog.mufanc.xyz/posts/2752488453/ 和https://nullptr.icu/index.php/archives/182/，可以扫描/memfd:jit-cache里面是否存在`zygisk_module_entry`

```c++
void scan_zygisk() {
    const char *prefix[] = {
            "zygisk_module_entry"
    };
    FILE *fp = fopen("/proc/self/maps", "r");
    char *left, *right;
    char perm[8], file[512];
    while (fscanf(fp, "%p-%p %s %*s %*s %*s %[^\n]s", &left, &right, perm, file) != EOF) {
        if (perm[0] == 'r' && perm[2] == 'x') {
            size_t size = right - left;
            for (auto &pattern: prefix) {
                if (memmem(left, size, pattern, strlen(pattern))) {
                    char *ptr = file;
                    while (isspace(ptr[0]) && ptr < file + sizeof(file)) ptr++;
                    LOGW("Found \"%s\" in %p-%p (%s)", pattern, left, right, file);
                    LOGW("/proc/%d/map_files/%lx-%lx", getpid(),
                            reinterpret_cast<uintptr_t>(left), reinterpret_cast<uintptr_t>(right)
                    );
                }
            }
        }
    }
}
```

这里测试中并未成功，观察发现可能是加载libAnswer.so时已注入完毕，想要检测可能需要调整一下。

### cheat程序

由于安卓沙箱机制的原因，且该程序并没有对游戏数据进行修改，如果不进行提权，检测外挂的难度较高。经过搜索分析发现大概有几种检测方法。

#### 检测1

由于程序采取syscall process_vm_readv方式远程获取游戏内存数据，可以考虑使用mincore内存缺页检测。原理是mmap在创建内存映射时未访问的内存页并不会创建。通过在游戏中创建不会访问的内存，让外挂遍历时访问到该地址，使得该内存变成非缺页状态。需要找到libUE4.so中不会去读取而外挂会读取的位置挖坑检测。

https://pshocker.github.io/2022/05/08/Android%E5%86%85%E5%AD%98%E8%AF%BB%E5%86%99%E6%A3%80%E6%B5%8B-mincore/

![image-20250413004712611](https://img.0a0.moe/od/01tklsjzahdvi7y3vkwvbk6oarjlecg5a3)

来源：https://bbs.kanxue.com/thread-284041.htm，想知道另外一个方法是什么

#### 检测2

程序使用imGUI绘制外挂页面，可以考虑检测imGUI绘制的某些特定位置，如人物射线的中心红点、自瞄的黄圈、绘制的ui。通过OpenGL提供的接口`glReadPixels()`获取屏幕进行检测。

```c++
void saveRawScreenshot(const char* path, int width, int height) {
    sleep(10);
    int size = width * height * 4; // RGBA8888
    auto* pixels = new uint8_t[size];

    // 读取像素，默认 OpenGL 原点在左下角
    glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels);

    // 翻转 Y 轴（因为 raw 通常期望从上往下读）
    auto* flipped = new uint8_t[size];
    for (int y = 0; y < height; ++y) {
        memcpy(flipped + y * width * 4,
               pixels + (height - 1 - y) * width * 4,
               width * 4);
    }

    // 保存为 .raw 文件
    std::ofstream file(path, std::ios::out | std::ios::binary);
    file.write(reinterpret_cast<const char*>(flipped), size);
    file.close();

    delete[] pixels;
    delete[] flipped;
}
```

未成功，返回全0，好像是缺少OpenGL 上下文



改用root获取屏幕内容后判断是否存在异常像素 ff0000的透视和ffff00的自瞄

```c++
void check_raw_screenshot_once() {
    while (true) {
        sleep(10);
        FILE* fp = popen("su -c screencap", "r");
        if (!fp) {
            LOGW("Failed to run screencap");
            return;
        }

        uint32_t width, height, format;
        if (fread(&width, sizeof(uint32_t), 1, fp) != 1 ||
            fread(&height, sizeof(uint32_t), 1, fp) != 1 ||
            fread(&format, sizeof(uint32_t), 1, fp) != 1) {
            LOGW("Failed to read header");
            pclose(fp);
            return;
        }

        if (format != 1) {  // 1 = RGBA_8888
            LOGW("Unsupported format: %u", format);
            pclose(fp);
            return;
        }

        size_t pixel_count = width * height;
        std::vector<uint8_t> buffer(pixel_count * 4);
        size_t read_bytes = fread(buffer.data(), 1, buffer.size(), fp);
        pclose(fp);

        if (read_bytes != buffer.size()) {
            LOGW("Read incomplete frame buffer (%zu/%zu)", read_bytes, buffer.size());
            return;
        }

        int red_count = 0;
        int yellow_count = 0;

        for (size_t i = 0; i < pixel_count; ++i) {
            uint8_t r = buffer[i * 4 + 0];
            uint8_t g = buffer[i * 4 + 1];
            uint8_t b = buffer[i * 4 + 2];

            if (r == 255 && g == 0 && b == 0) {
                red_count++;
            } else if (r == 255 && g == 255 && b == 0) {
                yellow_count++;
            }
        }
        if (red_count > 0 || yellow_count > 0) {
            LOGW(">>> [check_raw_screenshot_once] Detected red/yellow pixels");
            FILE* log_file = fopen(LOGPATH, "a");
            if (log_file) {
                char time_buffer[64];
                get_current_time(time_buffer, sizeof(time_buffer));
                fprintf(log_file, "%s [!] Detected red/yellow pixels: Red: %d, Yellow: %d\n", time_buffer, red_count, yellow_count);
                fclose(log_file);
            }
        }
    }
}

```

检测到不存在于游戏的颜色可判断外挂

#### 检测3

黑名单应用，判断是否存在可疑进程（需要root）

```c++
void check_cheat_running() {
    while (true) {
        std::string cmd = "su -c ps -ef | grep cheat | grep -v grep > /dev/null";  // 此处申请了 root 权限
        int result = system(cmd.c_str());
        if (result == 0) {
            LOGW(">>> [check_cheat_running] Cheat progress detected!");
            FILE* log_file = fopen(LOGPATH, "a");
            if (log_file) {
                fprintf(log_file, "[!] Detected cheat process running\n");
                fclose(log_file);
            }
            return;
        }
        sleep(5);
    }
}
```

#### 检测4

利用eBPF对syscall进行检测，筛选出syscall 270远程读取进程数据的操作（需要root）

#### 检测5

有root权限条件下可以扫内存，检测关键字符串"自瞄"、"透视"、"imgui"等（需要root）

```c++
void check_imgui_in_cheat() {
    while (true) {
        FILE* pipe = popen("su -c \"ps -ef | grep cheat | grep -v grep\"", "r");
        if (!pipe) {
            perror("popen failed");
            sleep(5);
            continue;
        }

        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            // 假设 PID 在第二列（根据 ps 具体格式可能需要调整）
            char user[64], pid[16];
            sscanf(buffer, "%s %s", user, pid);

            // 构建获取进程路径的命令
            char exe_path_cmd[128];
            snprintf(exe_path_cmd, sizeof(exe_path_cmd), "su -c \"readlink /proc/%s/exe\"", pid);

            FILE* exe_pipe = popen(exe_path_cmd, "r");
            if (!exe_pipe) {
                perror("popen exe_path_cmd failed");
                continue;
            }

            char exe_path[256];
            if (fgets(exe_path, sizeof(exe_path), exe_pipe)) {
                // 移除结尾换行符
                exe_path[strcspn(exe_path, "\n")] = 0;

                // 构造 strings + grep 命令
                char check_cmd[512];
                snprintf(check_cmd, sizeof(check_cmd), "su -c \"strings '%s' | grep -i imgui > /dev/null\"", exe_path);

                int result = system(check_cmd);
                if (result == 0) {
                    LOGW(">>> [check_imgui_in_cheat] Found imgui in cheat process: %s", exe_path);
                    FILE* log_file = fopen(LOGPATH, "a");
                    if (log_file) {
                        fprintf(log_file, "[!] Detected imgui string in process: %s\n", exe_path);
                        fclose(log_file);
                        pclose(exe_pipe);
                        pclose(pipe);
                        return;
                    }
                }
            }
            pclose(exe_pipe);
        }
        pclose(pipe);
        sleep(5);
    }
}
```

#### 检测6（猜想）

由于imGUI会拦截触摸事件，可以通过检测屏幕的触摸事件与游戏接收到的触摸事件是否一致，不一致说明游戏上面有其他东西拦截了。这点同理可用于自瞄的检测。实际的触控与输入到游戏的触控不一致。

## 全部代码

```c++
#include <pthread.h>
#include <dirent.h>
#include <android/log.h>
#include <sys/stat.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <fstream>
#include <ctime>
#include <vector>


#define TAG "Answer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#define LOGPATH "/data/data/com.ACE2025.Game/CheatDetection.log"

void* get_module_base(const char* module_name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            uintptr_t base_addr = 0;
            sscanf(line, "%lx-%*lx", &base_addr);
            fclose(fp);
            return (void*)base_addr;
        }
    }
    fclose(fp);
    return nullptr;
}

void get_current_time(char* buffer, size_t size) {
    time_t now = time(nullptr);
    struct tm* tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

void check_libUE4_modified(void* base) {
    sleep(5);
    uintptr_t offset = 0x6711AC4;
    uintptr_t target = (uintptr_t)base + offset;
    uint32_t value = *(uint32_t*)target;
    LOGI(">>> [check_libUE4_modified] Value at offset: %u", value);
    if (value != 1386746888) {
        LOGW(">>> [check_libUE4_modified] Value has been modified!");
        FILE* log_file = fopen(LOGPATH, "a");
        if (log_file) {
            char time_buffer[64];
            get_current_time(time_buffer, sizeof(time_buffer));
            fprintf(log_file, "%s [!] Detected modification in libUE4.so\n", time_buffer);
            fclose(log_file);
        }
    }
}

void check_libUE4_rwxp_segment() {
    sleep(4);
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libUE4.so")) {
            if (strstr(line, "rwxp")) {
                fclose(fp);
                LOGW(">>> [check_libUE4_rwxp_segment] Found rwxp segment: %s", line);
                FILE* log_file = fopen(LOGPATH, "a");
                if (log_file) {
                    char time_buffer[64];
                    get_current_time(time_buffer, sizeof(time_buffer));
                    fprintf(log_file, "%s [!] Detected rwxp segment in libUE4.so: %s\n", time_buffer, line);
                    fclose(log_file);
                }
                return;
            }
        }
    }
    fclose(fp);
}

void check_libGame_injected() {
    sleep(3);
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libGame.so")) {
            fclose(fp);
            LOGW(">>> [check_libGame_injected] Found libGame.so: %s", line);
            FILE* log_file = fopen(LOGPATH, "a");
            if (log_file) {
                char time_buffer[64];
                get_current_time(time_buffer, sizeof(time_buffer));
                fprintf(log_file, "%s [!] Detected libGame.so injection: %s\n", time_buffer, line);
                fclose(log_file);
            }
            return;
        }
    }
    fclose(fp);
}


void scan_directory_for_libGame(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat st{};
        if (stat(fullpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                scan_directory_for_libGame(fullpath);  // 递归子目录
            } else if (S_ISREG(st.st_mode)) {
                if (strcmp(entry->d_name, "libGame.so") == 0) {
                    LOGW(">>> [scan_directory_for_libGame] Found suspicious file: %s", fullpath);
                    FILE* log_file = fopen(LOGPATH, "a");
                    if (log_file) {
                        char time_buffer[64];
                        get_current_time(time_buffer, sizeof(time_buffer));
                        fprintf(log_file, "%s [!] Detected suspicious file: %s\n", time_buffer, fullpath);
                        fclose(log_file);
                    }
                }
            }
        }
    }
    closedir(dir);
}


void scan_zygisk() {
    const char *prefix[] = {
            "zygisk_module_entry"
    };
    FILE *fp = fopen("/proc/self/maps", "r");
    char *left, *right;
    char perm[8], file[512];
    while (fscanf(fp, "%p-%p %s %*s %*s %*s %[^\n]s", &left, &right, perm, file) != EOF) {
        if (perm[0] == 'r' && perm[2] == 'x') {
            size_t size = right - left;
            for (auto &pattern: prefix) {
                if (memmem(left, size, pattern, strlen(pattern))) {
                    char *ptr = file;
                    while (isspace(ptr[0]) && ptr < file + sizeof(file)) ptr++;
                    LOGW("Found \"%s\" in %p-%p (%s)", pattern, left, right, file);
                    LOGW("/proc/%d/map_files/%lx-%lx", getpid(),
                            reinterpret_cast<uintptr_t>(left), reinterpret_cast<uintptr_t>(right)
                    );
                }
            }
        }
    }
}

void check_cheat_running() {
    while (true) {
        std::string cmd = "su -c ps -ef | grep cheat | grep -v grep > /dev/null";
        int result = system(cmd.c_str());
        if (result == 0) {
            LOGW(">>> [check_cheat_running] Cheat progress detected!");
            FILE* log_file = fopen(LOGPATH, "a");
            if (log_file) {
                char time_buffer[64];
                get_current_time(time_buffer, sizeof(time_buffer));
                fprintf(log_file, "%s [!] Detected cheat process running\n", time_buffer);
                fclose(log_file);
            }
            return;
        }
        sleep(5);
    }
}

void check_imgui_in_cheat() {
    while (true) {
        FILE* pipe = popen("su -c \"ps -ef | grep cheat | grep -v grep\"", "r");
        if (!pipe) {
            perror("popen failed");
            sleep(5);
            continue;
        }

        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            // 假设 PID 在第二列（根据 ps 具体格式可能需要调整）
            char user[64], pid[16];
            sscanf(buffer, "%s %s", user, pid);

            // 构建获取进程路径的命令
            char exe_path_cmd[128];
            snprintf(exe_path_cmd, sizeof(exe_path_cmd), "su -c \"readlink /proc/%s/exe\"", pid);

            FILE* exe_pipe = popen(exe_path_cmd, "r");
            if (!exe_pipe) {
                perror("popen exe_path_cmd failed");
                continue;
            }

            char exe_path[256];
            if (fgets(exe_path, sizeof(exe_path), exe_pipe)) {
                // 移除结尾换行符
                exe_path[strcspn(exe_path, "\n")] = 0;

                // 构造 strings + grep 命令
                char check_cmd[512];
                snprintf(check_cmd, sizeof(check_cmd), "su -c \"strings '%s' | grep -i imgui > /dev/null\"", exe_path);

                int result = system(check_cmd);
                if (result == 0) {
                    LOGW(">>> [check_imgui_in_cheat] Found imgui string in cheat process: %s", exe_path);
                    FILE* log_file = fopen(LOGPATH, "a");
                    if (log_file) {
                        char time_buffer[64];
                        get_current_time(time_buffer, sizeof(time_buffer));
                        fprintf(log_file, "%s [!] Detected imgui string in cheat process: %s\n", time_buffer, exe_path);
                        fclose(log_file);
                        pclose(exe_pipe);
                        pclose(pipe);
                        return;
                    }
                }
            }
            pclose(exe_pipe);
        }
        pclose(pipe);
        sleep(5);
    }
}

void saveRawScreenshot(const char* path, int width, int height) {
    sleep(10);
    int size = width * height * 4; // RGBA8888
    auto* pixels = new uint8_t[size];

    // 读取像素，默认 OpenGL 原点在左下角
    glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels);

    // 翻转 Y 轴（因为 raw 通常期望从上往下读）
    auto* flipped = new uint8_t[size];
    for (int y = 0; y < height; ++y) {
        memcpy(flipped + y * width * 4,
               pixels + (height - 1 - y) * width * 4,
               width * 4);
    }

    // 保存为 .raw 文件
    std::ofstream file(path, std::ios::out | std::ios::binary);
    file.write(reinterpret_cast<const char*>(flipped), size);
    file.close();

    delete[] pixels;
    delete[] flipped;
}


void check_raw_screenshot_once() {
    while (true) {
        sleep(10);
        FILE* fp = popen("su -c screencap", "r");
        if (!fp) {
            LOGW("Failed to run screencap");
            return;
        }

        uint32_t width, height, format;
        if (fread(&width, sizeof(uint32_t), 1, fp) != 1 ||
            fread(&height, sizeof(uint32_t), 1, fp) != 1 ||
            fread(&format, sizeof(uint32_t), 1, fp) != 1) {
            LOGW("Failed to read header");
            pclose(fp);
            return;
        }

        if (format != 1) {  // 1 = RGBA_8888
            LOGW("Unsupported format: %u", format);
            pclose(fp);
            return;
        }

        size_t pixel_count = width * height;
        std::vector<uint8_t> buffer(pixel_count * 4);
        size_t read_bytes = fread(buffer.data(), 1, buffer.size(), fp);
        pclose(fp);

        if (read_bytes != buffer.size()) {
            LOGW("Read incomplete frame buffer (%zu/%zu)", read_bytes, buffer.size());
            return;
        }

        int red_count = 0;
        int yellow_count = 0;

        for (size_t i = 0; i < pixel_count; ++i) {
            uint8_t r = buffer[i * 4 + 0];
            uint8_t g = buffer[i * 4 + 1];
            uint8_t b = buffer[i * 4 + 2];

            if (r == 255 && g == 0 && b == 0) {
                red_count++;
            } else if (r == 255 && g == 255 && b == 0) {
                yellow_count++;
            }
        }
        if (red_count > 0 || yellow_count > 0) {
            LOGW(">>> [check_raw_screenshot_once] Detected red/yellow pixels");
            FILE* log_file = fopen(LOGPATH, "a");
            if (log_file) {
                char time_buffer[64];
                get_current_time(time_buffer, sizeof(time_buffer));
                fprintf(log_file, "%s [!] Detected red/yellow pixels: Red: %d, Yellow: %d\n", time_buffer, red_count, yellow_count);
                fclose(log_file);
            }
        }
    }
}



__attribute__((constructor))
void on_library_loaded() {
    LOGI(">>> [constructor] Library loaded");

    // 在/data/data/com.ACE2025.Game 目录下创建一个log文件
    FILE* log_file = fopen(LOGPATH, "a");
    if (log_file) {
        char time_buffer[64];
        get_current_time(time_buffer, sizeof(time_buffer));
        fprintf(log_file, "%s [*] Library loaded\n", time_buffer);
        fclose(log_file);
    } else {
        LOGE("Failed to create log file");
    }

    // 获取 libUE4.so 的基址
    void* base = get_module_base("libUE4.so");
    if (!base) {
        LOGE("Failed to find libUE4.so base");
        return;
    }

    pthread_t checkThread1, checkThread2, checkThread3, checkThread4, checkThread5, checkThread6, checkThread7, checkThread8;

    // 检测 libUE4.so 是否被修改
    pthread_create(&checkThread1, nullptr, [](void*) -> void* {
        check_libUE4_rwxp_segment();
        return nullptr;
    }, nullptr);
    pthread_detach(checkThread1);

    pthread_create(&checkThread2, nullptr, [](void* arg) -> void* {
        void* base = arg;
        check_libUE4_modified(base);
        return nullptr;
    }, base);
    pthread_detach(checkThread2);

    // 扫描 zygisk 痕迹
    pthread_create(&checkThread3, nullptr, [](void*) -> void* {
        scan_zygisk();
        return nullptr;
    }, nullptr);
    pthread_detach(checkThread3);

    // 检测 libGame.so 是否被注入
    pthread_create(&checkThread4, nullptr, [](void*) -> void* {
        check_libGame_injected();
        return nullptr;
    }, nullptr);
    pthread_detach(checkThread4);

    // 扫描 /data/data/com.ACE2025.Game 目录
    const char* path = "/data/data/com.ACE2025.Game";
    pthread_create(&checkThread5, nullptr, [](void* arg) -> void* {
        const char* path = (const char*)arg;
        scan_directory_for_libGame(path);
        return nullptr;
    }, (void*)path);
    pthread_detach(checkThread5);

    // 检测是否有 cheat 进程在运行
    pthread_create(&checkThread6, nullptr, [](void*) -> void* {
        check_cheat_running();
        return nullptr;
    }, nullptr);
    pthread_detach(checkThread6);

    // 检测 cheat 进程中是否有 imgui
    pthread_create(&checkThread7, nullptr, [](void*) -> void* {
        check_imgui_in_cheat();
        return nullptr;
    }, nullptr);
    pthread_detach(checkThread7);

    // 检测截图
    pthread_create(&checkThread8, nullptr, [](void*) -> void* {
        check_raw_screenshot_once();
        return nullptr;
    }, nullptr);
    pthread_detach(checkThread8);


//    // 截图并保存为 .raw 文件
//    int width = 500;
//    int height = 500;
//    const char* screenshot_path = "/data/data/com.ACE2025.Game/screenshot.raw";
//    pthread_t screenshotThread;
//    pthread_create(&screenshotThread, nullptr, [](void* arg) -> void* {
//        auto* args = (std::tuple<const char*, int, int>*)arg;
//        const char* path = std::get<0>(*args);
//        int width = std::get<1>(*args);
//        int height = std::get<2>(*args);
//        saveRawScreenshot(path, width, height);
//        delete args;
//        return nullptr;
//    }, new std::tuple<const char*, int, int>(screenshot_path, width, height));

}
```
