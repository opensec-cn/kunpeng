/**
 * @Author: wstart
 * @Date: 2019-02-14
 * @Version 0.1
 * @Desc: kunpeng JAVA 版本实现
 * 环境：jdk1.8 ,jna 5.2.0 , mac
 * 1. 请先下载 JNA的jar包  http://repo1.maven.org/maven2/net/java/dev/jna/jna/5.2.0/jna-5.2.0.jar
 * 2. 添加到项目中去，https://zyjustin9.iteye.com/blog/2172445
 * 3. 引入com.sun.jna.Library，com.sun.jna.Native
 * 4. 创建 Kunpeng interface
 * 5. 引入 Kunpeng
 * 6. 编写对应的方法
 * 其他: 对应的类型转换对照表： https://github.com/java-native-access/jna/blob/master/www/Mappings.md
 *
 */

import com.sun.jna.Library;
import com.sun.jna.Native;

public class Kunpeng_exp {

    public interface Kunpeng extends Library {
        Kunpeng INSTANCE = (Kunpeng)Native.load("/YourPath/kunpeng_c.dylib", Kunpeng.class);
        public void StartWebServer();
    }


    public static void main(String[] args) {
        System.out.println("Hello Kunpeng");
        Kunpeng.INSTANCE.StartWebServer();
    }
}
