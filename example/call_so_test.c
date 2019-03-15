// 编译方法: gcc -o kso -g call_so_test.c -ldl
#include <stdio.h>
#include <dlfcn.h>

int main(){
    printf("======== Start Kunpeng Tesing ==========================================================\n");
    char c;
    char *so_path = "../kunpeng_c.so";
    void* handle = dlopen(so_path, RTLD_LAZY);


    // 做函数的定义及map
    void (*ShowLog)();
    char* (*GetPlugins)();
    char* (*GetVersion)();
    void (*StartWebServer)(char* );
    char* (*Check)(char*);
    void (*SetConfig)(char* );
    void (*StartBuffer)();
    char* (*GetLog)(char*);

    ShowLog = dlsym(handle,"ShowLog");
    GetPlugins = dlsym(handle,"GetPlugins");
    GetVersion = dlsym(handle,"GetVersion");
    StartWebServer = dlsym(handle,"StartWebServer");
    Check = dlsym(handle,"Check");
    SetConfig = dlsym(handle,"SetConfig");
    StartBuffer = dlsym(handle,"StartBuffer");
    GetLog = dlsym(handle,"GetLog");

    //ShowLog();
    char *plugins = GetPlugins();
    //printf("plugins in kunpeng : %s \n ",plugins);

    char *version = GetVersion();
    printf("kunpeng %s loaded , version : %s \n",so_path,GetVersion());

    char *task = "{\"type\":\"web\",\"netloc\":\"http://sec.sina.com.cn\",\"target\":\"web\"}";
    StartBuffer();
    char *result = Check(task);
    printf("scan task :\n %s \n , scan result:\n%s\n",task,result);
    printf("scan log :\n%s\n",GetLog(""));
    

    printf("Start WebApi : \n");
    StartWebServer("0.0.0.0:4004");
    printf("Webapi Serve: 0.0.0.0:4004\n");
    scanf("%c",&c);

    printf("kunpeng test ended!\n");
    printf("======== End Kunpeng Tesing ==========================================================\n");
    return 0;
}


