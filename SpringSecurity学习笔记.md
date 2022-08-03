<h1 style="color:skyblue;text-align:center">Spring Security学习笔记</h1>







---



# 简介

Spring 是非常流行和成功的 Java 应用开发框架，Spring Security 正是 Spring 家族中的 成员。Spring Security 基于 Spring 框架，提供了一套 Web 应用安全性的完整解决方案。

关于安全方面的两个主要区域是“认证”和“授权”（或者访问控 制），一般来说，Web 应用的安全性包括用户认证（Authentication）和用户授权 （Authorization）两个部分，这两点也是 Spring Security 重要核心功能

* 用户认证指的是：验证某个用户是否为系统中的合法主体，也就是说用户能否访问 该系统。用户认证一般要求用户提供用户名和密码。系统通过校验用户名和密码来完成认 证过程。通俗点说就是系统认为用户是否能登录
* 用户授权指的是验证某个用户是否有权限执行某个操作。在一个系统中，不同用户 所具有的权限是不同的。比如对一个文件来说，有的用户只能进行读取，而有的用户可以 进行修改。一般来说，系统会为不同的用户分配不同的角色，而每个角色则对应一系列的 权限。通俗点讲就是系统判断用户是否有权限去做某些事情





# 特点

* 和 Spring 无缝整合
* 全面的权限控制
* 专门为 Web 开发而设计
  * 旧版本不能脱离 Web 环境使用
  * 新版本对整个框架进行了分层抽取，分成了核心模块和 Web 模块。单独引入核心模块就可以脱离 Web 环境
* 重量级







# 案例

## 创建spring boot项目

名字为springSecurity_demo



![image-20220730195542410](img/SpringSecurity学习笔记/image-20220730195542410.png)









## pom文件



```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.2</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>mao</groupId>
    <artifactId>springSecurity_demo</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>springSecurity_demo</name>
    <description>springSecurity_demo</description>
    <properties>
        <java.version>11</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!-- spring security 安全框架依赖 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <!-- spring security 安全框架测试依赖 -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>

    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```





## 配置类



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录
        http.formLogin()
                .and()
                //认证配置
                .authorizeRequests()
                //如何请求都需要身份认证
                .anyRequest().authenticated();

    }
}
```







## 启动服务



```sh
OpenJDK 64-Bit Server VM warning: Options -Xverify:none and -noverify were deprecated in JDK 13 and will likely be removed in a future release.

  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::                (v2.7.2)

2022-07-30 20:45:49.478  INFO 4904 --- [           main] m.s.SpringSecurityDemoApplication        : Starting SpringSecurityDemoApplication using Java 16.0.2 on mao with PID 4904 (H:\程序\大三暑假\springSecurity_demo\target\classes started by mao in H:\程序\大三暑假\springSecurity_demo)
2022-07-30 20:45:49.480 DEBUG 4904 --- [           main] m.s.SpringSecurityDemoApplication        : Running with Spring Boot v2.7.2, Spring v5.3.22
2022-07-30 20:45:49.480  INFO 4904 --- [           main] m.s.SpringSecurityDemoApplication        : The following 1 profile is active: "dev"
2022-07-30 20:45:50.123  INFO 4904 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat initialized with port(s): 8080 (http)
2022-07-30 20:45:50.130  INFO 4904 --- [           main] o.apache.catalina.core.StandardService   : Starting service [Tomcat]
2022-07-30 20:45:50.130  INFO 4904 --- [           main] org.apache.catalina.core.StandardEngine  : Starting Servlet engine: [Apache Tomcat/9.0.65]
2022-07-30 20:45:50.200  INFO 4904 --- [           main] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring embedded WebApplicationContext
2022-07-30 20:45:50.200  INFO 4904 --- [           main] w.s.c.ServletWebServerApplicationContext : Root WebApplicationContext: initialization completed in 686 ms
2022-07-30 20:45:50.434  WARN 4904 --- [           main] .s.s.UserDetailsServiceAutoConfiguration : 

Using generated security password: 9c652816-7891-4bf2-b4da-a1d6cbf08221

This generated password is for development use only. Your security configuration must be updated before running your application in production.

2022-07-30 20:45:50.484  INFO 4904 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Will secure any request with [org.springframework.security.web.session.DisableEncodeUrlFilter@1d901f20, org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@6d08b4e6, org.springframework.security.web.context.SecurityContextPersistenceFilter@28369db0, org.springframework.security.web.header.HeaderWriterFilter@36920bd6, org.springframework.security.web.csrf.CsrfFilter@5fef2aac, org.springframework.security.web.authentication.logout.LogoutFilter@6bfaa0a6, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@76e9f00b, org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter@7cf78c85, org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter@1015a4b9, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@2e86807a, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@40d23c82, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@1acb74ad, org.springframework.security.web.session.SessionManagementFilter@6bee793f, org.springframework.security.web.access.ExceptionTranslationFilter@205df5dc, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@695c938d]
2022-07-30 20:45:50.518  INFO 4904 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8080 (http) with context path ''
2022-07-30 20:45:50.527  INFO 4904 --- [           main] m.s.SpringSecurityDemoApplication        : Started SpringSecurityDemoApplication in 1.367 seconds (JVM running for 1.79)
```





## 访问



http://localhost:8080/



![image-20220730204724415](img/SpringSecurity学习笔记/image-20220730204724415.png)





默认的用户名：user

密码在项目启动的时候在控制台会打印



![image-20220730204827050](img/SpringSecurity学习笔记/image-20220730204827050.png)











# 概念



## 主体

使用系统的用户或设备或从其他系统远程登录的用户等等。简单说就是谁使用系统谁就是主体



## 认证

权限管理系统确认一个主体的身份，允许主体进入系统。简单说就是“主体”证明自己是谁



## 授权

将操作系统的“权力”“授予”“主体”，这样主体就具备了操作系统中特定功能的能力







# 基本原理

SpringSecurity 本质是一个过滤器链



## FilterSecurityInterceptor



是一个方法级的权限过滤器, 基本位于过滤链的最底部



```java
package org.springframework.security.web.access.intercept;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;

/**
 * Performs security handling of HTTP resources via a filter implementation.
 * <p>
 * The <code>SecurityMetadataSource</code> required by this security interceptor is of
 * type {@link FilterInvocationSecurityMetadataSource}.
 * <p>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 * </p>
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {

   private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

   private FilterInvocationSecurityMetadataSource securityMetadataSource;

   private boolean observeOncePerRequest = true;

   /**
    * Not used (we rely on IoC container lifecycle services instead)
    * @param arg0 ignored
    *
    */
   @Override
   public void init(FilterConfig arg0) {
   }

   /**
    * Not used (we rely on IoC container lifecycle services instead)
    */
   @Override
   public void destroy() {
   }

   /**
    * Method that is actually called by the filter chain. Simply delegates to the
    * {@link #invoke(FilterInvocation)} method.
    * @param request the servlet request
    * @param response the servlet response
    * @param chain the filter chain
    * @throws IOException if the filter chain fails
    * @throws ServletException if the filter chain fails
    */
   @Override
   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
         throws IOException, ServletException {
      invoke(new FilterInvocation(request, response, chain));
   }

   public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
      return this.securityMetadataSource;
   }

   @Override
   public SecurityMetadataSource obtainSecurityMetadataSource() {
      return this.securityMetadataSource;
   }

   public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource newSource) {
      this.securityMetadataSource = newSource;
   }

   @Override
   public Class<?> getSecureObjectClass() {
      return FilterInvocation.class;
   }

   public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
      if (isApplied(filterInvocation) && this.observeOncePerRequest) {
         // filter already applied to this request and user wants us to observe
         // once-per-request handling, so don't re-do security checking
         filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
         return;
      }
      // first time this request being called, so perform security checking
      if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
         filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
      }
      InterceptorStatusToken token = super.beforeInvocation(filterInvocation);
      try {
         filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
      }
      finally {
         super.finallyInvocation(token);
      }
      super.afterInvocation(token, null);
   }

   private boolean isApplied(FilterInvocation filterInvocation) {
      return (filterInvocation.getRequest() != null)
            && (filterInvocation.getRequest().getAttribute(FILTER_APPLIED) != null);
   }

   /**
    * Indicates whether once-per-request handling will be observed. By default this is
    * <code>true</code>, meaning the <code>FilterSecurityInterceptor</code> will only
    * execute once-per-request. Sometimes users may wish it to execute more than once per
    * request, such as when JSP forwards are being used and filter security is desired on
    * each included fragment of the HTTP request.
    * @return <code>true</code> (the default) if once-per-request is honoured, otherwise
    * <code>false</code> if <code>FilterSecurityInterceptor</code> will enforce
    * authorizations for each and every fragment of the HTTP request.
    */
   public boolean isObserveOncePerRequest() {
      return this.observeOncePerRequest;
   }

   public void setObserveOncePerRequest(boolean observeOncePerRequest) {
      this.observeOncePerRequest = observeOncePerRequest;
   }

}
```







## ExceptionTranslationFilter



是个异常过滤器，用来处理在认证授权过程中抛出的异常



```java
package org.springframework.security.web.access;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Handles any <code>AccessDeniedException</code> and <code>AuthenticationException</code>
 * thrown within the filter chain.
 * <p>
 * This filter is necessary because it provides the bridge between Java exceptions and
 * HTTP responses. It is solely concerned with maintaining the user interface. This filter
 * does not do any actual security enforcement.
 * <p>
 * If an {@link AuthenticationException} is detected, the filter will launch the
 * <code>authenticationEntryPoint</code>. This allows common handling of authentication
 * failures originating from any subclass of
 * {@link org.springframework.security.access.intercept.AbstractSecurityInterceptor}.
 * <p>
 * If an {@link AccessDeniedException} is detected, the filter will determine whether or
 * not the user is an anonymous user. If they are an anonymous user, the
 * <code>authenticationEntryPoint</code> will be launched. If they are not an anonymous
 * user, the filter will delegate to the
 * {@link org.springframework.security.web.access.AccessDeniedHandler}. By default the
 * filter will use
 * {@link org.springframework.security.web.access.AccessDeniedHandlerImpl}.
 * <p>
 * To use this filter, it is necessary to specify the following properties:
 * <ul>
 * <li><code>authenticationEntryPoint</code> indicates the handler that should commence
 * the authentication process if an <code>AuthenticationException</code> is detected. Note
 * that this may also switch the current protocol from http to https for an SSL
 * login.</li>
 * <li><tt>requestCache</tt> determines the strategy used to save a request during the
 * authentication process in order that it may be retrieved and reused once the user has
 * authenticated. The default implementation is {@link HttpSessionRequestCache}.</li>
 * </ul>
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class ExceptionTranslationFilter extends GenericFilterBean implements MessageSourceAware {

	private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();

	private AuthenticationEntryPoint authenticationEntryPoint;

	private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

	private RequestCache requestCache = new HttpSessionRequestCache();

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	public ExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint) {
		this(authenticationEntryPoint, new HttpSessionRequestCache());
	}

	public ExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint, RequestCache requestCache) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
		this.requestCache = requestCache;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.authenticationEntryPoint, "authenticationEntryPoint must be specified");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		try {
			chain.doFilter(request, response);
		}
		catch (IOException ex) {
			throw ex;
		}
		catch (Exception ex) {
			// Try to extract a SpringSecurityException from the stacktrace
			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
			RuntimeException securityException = (AuthenticationException) this.throwableAnalyzer
					.getFirstThrowableOfType(AuthenticationException.class, causeChain);
			if (securityException == null) {
				securityException = (AccessDeniedException) this.throwableAnalyzer
						.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
			}
			if (securityException == null) {
				rethrow(ex);
			}
			if (response.isCommitted()) {
				throw new ServletException("Unable to handle the Spring Security Exception "
						+ "because the response is already committed.", ex);
			}
			handleSpringSecurityException(request, response, chain, securityException);
		}
	}

	private void rethrow(Exception ex) throws ServletException {
		// Rethrow ServletExceptions and RuntimeExceptions as-is
		if (ex instanceof ServletException) {
			throw (ServletException) ex;
		}
		if (ex instanceof RuntimeException) {
			throw (RuntimeException) ex;
		}
		// Wrap other Exceptions. This shouldn't actually happen
		// as we've already covered all the possibilities for doFilter
		throw new RuntimeException(ex);
	}

	public AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	protected AuthenticationTrustResolver getAuthenticationTrustResolver() {
		return this.authenticationTrustResolver;
	}

	private void handleSpringSecurityException(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, RuntimeException exception) throws IOException, ServletException {
		if (exception instanceof AuthenticationException) {
			handleAuthenticationException(request, response, chain, (AuthenticationException) exception);
		}
		else if (exception instanceof AccessDeniedException) {
			handleAccessDeniedException(request, response, chain, (AccessDeniedException) exception);
		}
	}

	private void handleAuthenticationException(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, AuthenticationException exception) throws ServletException, IOException {
		this.logger.trace("Sending to authentication entry point since authentication failed", exception);
		sendStartAuthentication(request, response, chain, exception);
	}

	private void handleAccessDeniedException(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, AccessDeniedException exception) throws ServletException, IOException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		boolean isAnonymous = this.authenticationTrustResolver.isAnonymous(authentication);
		if (isAnonymous || this.authenticationTrustResolver.isRememberMe(authentication)) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Sending %s to authentication entry point since access is denied",
						authentication), exception);
			}
			sendStartAuthentication(request, response, chain,
					new InsufficientAuthenticationException(
							this.messages.getMessage("ExceptionTranslationFilter.insufficientAuthentication",
									"Full authentication is required to access this resource")));
		}
		else {
			if (logger.isTraceEnabled()) {
				logger.trace(
						LogMessage.format("Sending %s to access denied handler since access is denied", authentication),
						exception);
			}
			this.accessDeniedHandler.handle(request, response, exception);
		}
	}

	protected void sendStartAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			AuthenticationException reason) throws ServletException, IOException {
		// SEC-112: Clear the SecurityContextHolder's Authentication, as the
		// existing Authentication is no longer considered valid
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		SecurityContextHolder.setContext(context);
		this.requestCache.saveRequest(request, response);
		this.authenticationEntryPoint.commence(request, response, reason);
	}

	public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		Assert.notNull(accessDeniedHandler, "AccessDeniedHandler required");
		this.accessDeniedHandler = accessDeniedHandler;
	}

	public void setAuthenticationTrustResolver(AuthenticationTrustResolver authenticationTrustResolver) {
		Assert.notNull(authenticationTrustResolver, "authenticationTrustResolver must not be null");
		this.authenticationTrustResolver = authenticationTrustResolver;
	}

	public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
		Assert.notNull(throwableAnalyzer, "throwableAnalyzer must not be null");
		this.throwableAnalyzer = throwableAnalyzer;
	}

	/**
	 * @since 5.5
	 */
	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

	/**
	 * Default implementation of <code>ThrowableAnalyzer</code> which is capable of also
	 * unwrapping <code>ServletException</code>s.
	 */
	private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {

		/**
		 * @see org.springframework.security.web.util.ThrowableAnalyzer#initExtractorMap()
		 */
		@Override
		protected void initExtractorMap() {
			super.initExtractorMap();
			registerExtractor(ServletException.class, (throwable) -> {
				ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
				return ((ServletException) throwable).getRootCause();
			});
		}

	}

}
```





## UsernamePasswordAuthenticationFilter



对/login 的 POST 请求做拦截，校验表单中用户名，密码



```java
package org.springframework.security.web.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

/**
 * Processes an authentication form submission. Called
 * {@code AuthenticationProcessingFilter} prior to Spring Security 3.0.
 * <p>
 * Login forms must present two parameters to this filter: a username and password. The
 * default parameter names to use are contained in the static fields
 * {@link #SPRING_SECURITY_FORM_USERNAME_KEY} and
 * {@link #SPRING_SECURITY_FORM_PASSWORD_KEY}. The parameter names can also be changed by
 * setting the {@code usernameParameter} and {@code passwordParameter} properties.
 * <p>
 * This filter by default responds to the URL {@code /login}.
 *
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @author Luke Taylor
 * @since 3.0
 */
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";

	public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

	private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login",
			"POST");

	private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;

	private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;

	private boolean postOnly = true;

	public UsernamePasswordAuthenticationFilter() {
		super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
	}

	public UsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
		super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
		String username = obtainUsername(request);
		username = (username != null) ? username.trim() : "";
		String password = obtainPassword(request);
		password = (password != null) ? password : "";
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
				password);
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	/**
	 * Enables subclasses to override the composition of the password, such as by
	 * including additional values and a separator.
	 * <p>
	 * This might be used for example if a postcode/zipcode was required in addition to
	 * the password. A delimiter such as a pipe (|) should be used to separate the
	 * password and extended value(s). The <code>AuthenticationDao</code> will need to
	 * generate the expected password in a corresponding manner.
	 * </p>
	 * @param request so that request attributes can be retrieved
	 * @return the password that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	@Nullable
	protected String obtainPassword(HttpServletRequest request) {
		return request.getParameter(this.passwordParameter);
	}

	/**
	 * Enables subclasses to override the composition of the username, such as by
	 * including additional values and a separator.
	 * @param request so that request attributes can be retrieved
	 * @return the username that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	@Nullable
	protected String obtainUsername(HttpServletRequest request) {
		return request.getParameter(this.usernameParameter);
	}

	/**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
	}

	/**
	 * Sets the parameter name which will be used to obtain the username from the login
	 * request.
	 * @param usernameParameter the parameter name. Defaults to "username".
	 */
	public void setUsernameParameter(String usernameParameter) {
		Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
		this.usernameParameter = usernameParameter;
	}

	/**
	 * Sets the parameter name which will be used to obtain the password from the login
	 * request..
	 * @param passwordParameter the parameter name. Defaults to "password".
	 */
	public void setPasswordParameter(String passwordParameter) {
		Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
		this.passwordParameter = passwordParameter;
	}

	/**
	 * Defines whether only HTTP POST requests will be allowed by this filter. If set to
	 * true, and an authentication request is received which is not a POST request, an
	 * exception will be raised immediately and authentication will not be attempted. The
	 * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
	 * authentication.
	 * <p>
	 * Defaults to <tt>true</tt> but may be overridden by subclasses.
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

	public final String getUsernameParameter() {
		return this.usernameParameter;
	}

	public final String getPasswordParameter() {
		return this.passwordParameter;
	}

}
```







## UserDetailsService 接口

当什么也没有配置的时候，账号和密码是由 Spring Security 定义生成的。而在实际项目中 账号和密码都是从数据库中查询出来的。 所以我们要通过自定义逻辑控制认证逻辑

如果需要自定义逻辑时，只需要实现 UserDetailsService 接口即可



接口定义：

```java
package org.springframework.security.core.userdetails;

/**
 * Core interface which loads user-specific data.
 * <p>
 * It is used throughout the framework as a user DAO and is the strategy used by the
 * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider
 * DaoAuthenticationProvider}.
 *
 * <p>
 * The interface requires only one read-only method, which simplifies support for new
 * data-access strategies.
 *
 * @author Ben Alex
 * @see org.springframework.security.authentication.dao.DaoAuthenticationProvider
 * @see UserDetails
 */
public interface UserDetailsService {

	/**
	 * Locates the user based on the username. In the actual implementation, the search
	 * may possibly be case sensitive, or case insensitive depending on how the
	 * implementation instance is configured. In this case, the <code>UserDetails</code>
	 * object that comes back may have a username that is of a different case than what
	 * was actually requested..
	 * @param username the username identifying the user whose data is required.
	 * @return a fully populated user record (never <code>null</code>)
	 * @throws UsernameNotFoundException if the user could not be found or the user has no
	 * GrantedAuthority
	 */
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

}

```





返回值是UserDetails，这个类是系统默认的用户“主体”



```java
package org.springframework.security.core.userdetails;

import java.io.Serializable;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Provides core user information.
 *
 * <p>
 * Implementations are not used directly by Spring Security for security purposes. They
 * simply store user information which is later encapsulated into {@link Authentication}
 * objects. This allows non-security related user information (such as email addresses,
 * telephone numbers etc) to be stored in a convenient location.
 * <p>
 * Concrete implementations must take particular care to ensure the non-null contract
 * detailed for each method is enforced. See
 * {@link org.springframework.security.core.userdetails.User} for a reference
 * implementation (which you might like to extend or use in your code).
 *
 * @author Ben Alex
 * @see UserDetailsService
 * @see UserCache
 */
public interface UserDetails extends Serializable {

   /**
    * Returns the authorities granted to the user. Cannot return <code>null</code>.
    * @return the authorities, sorted by natural key (never <code>null</code>)
    */
   Collection<? extends GrantedAuthority> getAuthorities();

   /**
    * Returns the password used to authenticate the user.
    * @return the password
    */
   String getPassword();

   /**
    * Returns the username used to authenticate the user. Cannot return
    * <code>null</code>.
    * @return the username (never <code>null</code>)
    */
   String getUsername();

   /**
    * Indicates whether the user's account has expired. An expired account cannot be
    * authenticated.
    * @return <code>true</code> if the user's account is valid (ie non-expired),
    * <code>false</code> if no longer valid (ie expired)
    */
   boolean isAccountNonExpired();

   /**
    * Indicates whether the user is locked or unlocked. A locked user cannot be
    * authenticated.
    * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
    */
   boolean isAccountNonLocked();

   /**
    * Indicates whether the user's credentials (password) has expired. Expired
    * credentials prevent authentication.
    * @return <code>true</code> if the user's credentials are valid (ie non-expired),
    * <code>false</code> if no longer valid (ie expired)
    */
   boolean isCredentialsNonExpired();

   /**
    * Indicates whether the user is enabled or disabled. A disabled user cannot be
    * authenticated.
    * @return <code>true</code> if the user is enabled, <code>false</code> otherwise
    */
   boolean isEnabled();

}
```





实现类user：



```java
package org.springframework.security.core.userdetails;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 * Models core user information retrieved by a {@link UserDetailsService}.
 * <p>
 * Developers may use this class directly, subclass it, or write their own
 * {@link UserDetails} implementation from scratch.
 * <p>
 * {@code equals} and {@code hashcode} implementations are based on the {@code username}
 * property only, as the intention is that lookups of the same user principal object (in a
 * user registry, for example) will match where the objects represent the same user, not
 * just when all the properties (authorities, password for example) are the same.
 * <p>
 * Note that this implementation is not immutable. It implements the
 * {@code CredentialsContainer} interface, in order to allow the password to be erased
 * after authentication. This may cause side-effects if you are storing instances
 * in-memory and reusing them. If so, make sure you return a copy from your
 * {@code UserDetailsService} each time it is invoked.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class User implements UserDetails, CredentialsContainer {

   private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

   private static final Log logger = LogFactory.getLog(User.class);

   private String password;

   private final String username;

   private final Set<GrantedAuthority> authorities;

   private final boolean accountNonExpired;

   private final boolean accountNonLocked;

   private final boolean credentialsNonExpired;

   private final boolean enabled;

   /**
    * Calls the more complex constructor with all boolean arguments set to {@code true}.
    */
   public User(String username, String password, Collection<? extends GrantedAuthority> authorities) {
      this(username, password, true, true, true, true, authorities);
   }

   /**
    * Construct the <code>User</code> with the details required by
    * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}.
    * @param username the username presented to the
    * <code>DaoAuthenticationProvider</code>
    * @param password the password that should be presented to the
    * <code>DaoAuthenticationProvider</code>
    * @param enabled set to <code>true</code> if the user is enabled
    * @param accountNonExpired set to <code>true</code> if the account has not expired
    * @param credentialsNonExpired set to <code>true</code> if the credentials have not
    * expired
    * @param accountNonLocked set to <code>true</code> if the account is not locked
    * @param authorities the authorities that should be granted to the caller if they
    * presented the correct username and password and the user is enabled. Not null.
    * @throws IllegalArgumentException if a <code>null</code> value was passed either as
    * a parameter or as an element in the <code>GrantedAuthority</code> collection
    */
   public User(String username, String password, boolean enabled, boolean accountNonExpired,
         boolean credentialsNonExpired, boolean accountNonLocked,
         Collection<? extends GrantedAuthority> authorities) {
      Assert.isTrue(username != null && !"".equals(username) && password != null,
            "Cannot pass null or empty values to constructor");
      this.username = username;
      this.password = password;
      this.enabled = enabled;
      this.accountNonExpired = accountNonExpired;
      this.credentialsNonExpired = credentialsNonExpired;
      this.accountNonLocked = accountNonLocked;
      this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
   }

   @Override
   public Collection<GrantedAuthority> getAuthorities() {
      return this.authorities;
   }

   @Override
   public String getPassword() {
      return this.password;
   }

   @Override
   public String getUsername() {
      return this.username;
   }

   @Override
   public boolean isEnabled() {
      return this.enabled;
   }

   @Override
   public boolean isAccountNonExpired() {
      return this.accountNonExpired;
   }

   @Override
   public boolean isAccountNonLocked() {
      return this.accountNonLocked;
   }

   @Override
   public boolean isCredentialsNonExpired() {
      return this.credentialsNonExpired;
   }

   @Override
   public void eraseCredentials() {
      this.password = null;
   }

   private static SortedSet<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
      Assert.notNull(authorities, "Cannot pass a null GrantedAuthority collection");
      // Ensure array iteration order is predictable (as per
      // UserDetails.getAuthorities() contract and SEC-717)
      SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(new AuthorityComparator());
      for (GrantedAuthority grantedAuthority : authorities) {
         Assert.notNull(grantedAuthority, "GrantedAuthority list cannot contain any null elements");
         sortedAuthorities.add(grantedAuthority);
      }
      return sortedAuthorities;
   }

   /**
    * Returns {@code true} if the supplied object is a {@code User} instance with the
    * same {@code username} value.
    * <p>
    * In other words, the objects are equal if they have the same username, representing
    * the same principal.
    */
   @Override
   public boolean equals(Object obj) {
      if (obj instanceof User) {
         return this.username.equals(((User) obj).username);
      }
      return false;
   }

   /**
    * Returns the hashcode of the {@code username}.
    */
   @Override
   public int hashCode() {
      return this.username.hashCode();
   }

   @Override
   public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append(getClass().getName()).append(" [");
      sb.append("Username=").append(this.username).append(", ");
      sb.append("Password=[PROTECTED], ");
      sb.append("Enabled=").append(this.enabled).append(", ");
      sb.append("AccountNonExpired=").append(this.accountNonExpired).append(", ");
      sb.append("credentialsNonExpired=").append(this.credentialsNonExpired).append(", ");
      sb.append("AccountNonLocked=").append(this.accountNonLocked).append(", ");
      sb.append("Granted Authorities=").append(this.authorities).append("]");
      return sb.toString();
   }

   /**
    * Creates a UserBuilder with a specified user name
    * @param username the username to use
    * @return the UserBuilder
    */
   public static UserBuilder withUsername(String username) {
      return builder().username(username);
   }

   /**
    * Creates a UserBuilder
    * @return the UserBuilder
    */
   public static UserBuilder builder() {
      return new UserBuilder();
   }

   /**
    * <p>
    * <b>WARNING:</b> This method is considered unsafe for production and is only
    * intended for sample applications.
    * </p>
    * <p>
    * Creates a user and automatically encodes the provided password using
    * {@code PasswordEncoderFactories.createDelegatingPasswordEncoder()}. For example:
    * </p>
    *
    * <pre>
    * <code>
    * UserDetails user = User.withDefaultPasswordEncoder()
    *     .username("user")
    *     .password("password")
    *     .roles("USER")
    *     .build();
    * // outputs {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
    * System.out.println(user.getPassword());
    * </code> </pre>
    *
    * This is not safe for production (it is intended for getting started experience)
    * because the password "password" is compiled into the source code and then is
    * included in memory at the time of creation. This means there are still ways to
    * recover the plain text password making it unsafe. It does provide a slight
    * improvement to using plain text passwords since the UserDetails password is
    * securely hashed. This means if the UserDetails password is accidentally exposed,
    * the password is securely stored.
    *
    * In a production setting, it is recommended to hash the password ahead of time. For
    * example:
    *
    * <pre>
    * <code>
    * PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    * // outputs {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
    * // remember the password that is printed out and use in the next step
    * System.out.println(encoder.encode("password"));
    * </code> </pre>
    *
    * <pre>
    * <code>
    * UserDetails user = User.withUsername("user")
    *     .password("{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG")
    *     .roles("USER")
    *     .build();
    * </code> </pre>
    * @return a UserBuilder that automatically encodes the password with the default
    * PasswordEncoder
    * @deprecated Using this method is not considered safe for production, but is
    * acceptable for demos and getting started. For production purposes, ensure the
    * password is encoded externally. See the method Javadoc for additional details.
    * There are no plans to remove this support. It is deprecated to indicate that this
    * is considered insecure for production purposes.
    */
   @Deprecated
   public static UserBuilder withDefaultPasswordEncoder() {
      logger.warn("User.withDefaultPasswordEncoder() is considered unsafe for production "
            + "and is only intended for sample applications.");
      PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
      return builder().passwordEncoder(encoder::encode);
   }

   public static UserBuilder withUserDetails(UserDetails userDetails) {
      // @formatter:off
      return withUsername(userDetails.getUsername())
            .password(userDetails.getPassword())
            .accountExpired(!userDetails.isAccountNonExpired())
            .accountLocked(!userDetails.isAccountNonLocked())
            .authorities(userDetails.getAuthorities())
            .credentialsExpired(!userDetails.isCredentialsNonExpired())
            .disabled(!userDetails.isEnabled());
      // @formatter:on
   }

   private static class AuthorityComparator implements Comparator<GrantedAuthority>, Serializable {

      private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

      @Override
      public int compare(GrantedAuthority g1, GrantedAuthority g2) {
         // Neither should ever be null as each entry is checked before adding it to
         // the set. If the authority is null, it is a custom authority and should
         // precede others.
         if (g2.getAuthority() == null) {
            return -1;
         }
         if (g1.getAuthority() == null) {
            return 1;
         }
         return g1.getAuthority().compareTo(g2.getAuthority());
      }

   }

   /**
    * Builds the user to be added. At minimum the username, password, and authorities
    * should provided. The remaining attributes have reasonable defaults.
    */
   public static final class UserBuilder {

      private String username;

      private String password;

      private List<GrantedAuthority> authorities;

      private boolean accountExpired;

      private boolean accountLocked;

      private boolean credentialsExpired;

      private boolean disabled;

      private Function<String, String> passwordEncoder = (password) -> password;

      /**
       * Creates a new instance
       */
      private UserBuilder() {
      }

      /**
       * Populates the username. This attribute is required.
       * @param username the username. Cannot be null.
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       */
      public UserBuilder username(String username) {
         Assert.notNull(username, "username cannot be null");
         this.username = username;
         return this;
      }

      /**
       * Populates the password. This attribute is required.
       * @param password the password. Cannot be null.
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       */
      public UserBuilder password(String password) {
         Assert.notNull(password, "password cannot be null");
         this.password = password;
         return this;
      }

      /**
       * Encodes the current password (if non-null) and any future passwords supplied to
       * {@link #password(String)}.
       * @param encoder the encoder to use
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       */
      public UserBuilder passwordEncoder(Function<String, String> encoder) {
         Assert.notNull(encoder, "encoder cannot be null");
         this.passwordEncoder = encoder;
         return this;
      }

      /**
       * Populates the roles. This method is a shortcut for calling
       * {@link #authorities(String...)}, but automatically prefixes each entry with
       * "ROLE_". This means the following:
       *
       * <code>
       *     builder.roles("USER","ADMIN");
       * </code>
       *
       * is equivalent to
       *
       * <code>
       *     builder.authorities("ROLE_USER","ROLE_ADMIN");
       * </code>
       *
       * <p>
       * This attribute is required, but can also be populated with
       * {@link #authorities(String...)}.
       * </p>
       * @param roles the roles for this user (i.e. USER, ADMIN, etc). Cannot be null,
       * contain null values or start with "ROLE_"
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       */
      public UserBuilder roles(String... roles) {
         List<GrantedAuthority> authorities = new ArrayList<>(roles.length);
         for (String role : roles) {
            Assert.isTrue(!role.startsWith("ROLE_"),
                  () -> role + " cannot start with ROLE_ (it is automatically added)");
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
         }
         return authorities(authorities);
      }

      /**
       * Populates the authorities. This attribute is required.
       * @param authorities the authorities for this user. Cannot be null, or contain
       * null values
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       * @see #roles(String...)
       */
      public UserBuilder authorities(GrantedAuthority... authorities) {
         return authorities(Arrays.asList(authorities));
      }

      /**
       * Populates the authorities. This attribute is required.
       * @param authorities the authorities for this user. Cannot be null, or contain
       * null values
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       * @see #roles(String...)
       */
      public UserBuilder authorities(Collection<? extends GrantedAuthority> authorities) {
         this.authorities = new ArrayList<>(authorities);
         return this;
      }

      /**
       * Populates the authorities. This attribute is required.
       * @param authorities the authorities for this user (i.e. ROLE_USER, ROLE_ADMIN,
       * etc). Cannot be null, or contain null values
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       * @see #roles(String...)
       */
      public UserBuilder authorities(String... authorities) {
         return authorities(AuthorityUtils.createAuthorityList(authorities));
      }

      /**
       * Defines if the account is expired or not. Default is false.
       * @param accountExpired true if the account is expired, false otherwise
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       */
      public UserBuilder accountExpired(boolean accountExpired) {
         this.accountExpired = accountExpired;
         return this;
      }

      /**
       * Defines if the account is locked or not. Default is false.
       * @param accountLocked true if the account is locked, false otherwise
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       */
      public UserBuilder accountLocked(boolean accountLocked) {
         this.accountLocked = accountLocked;
         return this;
      }

      /**
       * Defines if the credentials are expired or not. Default is false.
       * @param credentialsExpired true if the credentials are expired, false otherwise
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       */
      public UserBuilder credentialsExpired(boolean credentialsExpired) {
         this.credentialsExpired = credentialsExpired;
         return this;
      }

      /**
       * Defines if the account is disabled or not. Default is false.
       * @param disabled true if the account is disabled, false otherwise
       * @return the {@link UserBuilder} for method chaining (i.e. to populate
       * additional attributes for this user)
       */
      public UserBuilder disabled(boolean disabled) {
         this.disabled = disabled;
         return this;
      }

      public UserDetails build() {
         String encodedPassword = this.passwordEncoder.apply(this.password);
         return new User(this.username, encodedPassword, !this.disabled, !this.accountExpired,
               !this.credentialsExpired, !this.accountLocked, this.authorities);
      }

   }

}
```









## PasswordEncoder 接口



密码转换器



encode：

对原始密码进行编码。通常，一个好的编码算法应用 SHA-1 或更大的散列与 8 字节或更大的随机生成的盐相结合。



matches：

验证从存储中获得的编码密码与提交的原始密码在编码后是否匹配。如果密码匹配，则返回 true，否则返回 false。存储的密码本身永远不会被解码。
参数：

* rawPassword - 编码和匹配的原始密码
* encodedPassword - 存储中要与之比较的编码密码





```java

package org.springframework.security.crypto.password;

/**
 * Service interface for encoding passwords.
 *
 * The preferred implementation is {@code BCryptPasswordEncoder}.
 *
 * @author Keith Donald
 */
public interface PasswordEncoder {

   /**
    * Encode the raw password. Generally, a good encoding algorithm applies a SHA-1 or
    * greater hash combined with an 8-byte or greater randomly generated salt.
    */
   String encode(CharSequence rawPassword);

   /**
    * Verify the encoded password obtained from storage matches the submitted raw
    * password after it too is encoded. Returns true if the passwords match, false if
    * they do not. The stored password itself is never decoded.
    * @param rawPassword the raw password to encode and match
    * @param encodedPassword the encoded password from storage to compare with
    * @return true if the raw password, after encoding, matches the encoded password from
    * storage
    */
   boolean matches(CharSequence rawPassword, String encodedPassword);

   /**
    * Returns true if the encoded password should be encoded again for better security,
    * else false. The default implementation always returns false.
    * @param encodedPassword the encoded password to check
    * @return true if the encoded password should be encoded again for better security,
    * else false.
    */
   default boolean upgradeEncoding(String encodedPassword) {
      return false;
   }

}
```





BCryptPasswordEncoder 是 Spring Security 官方推荐的密码解析器，平时多使用这个解析 器。 BCryptPasswordEncoder 是对 bcrypt 强散列方法的具体实现。是基于 Hash 算法实现的单 向加密。可以通过 strength 控制加密强度，默认 10



![image-20220731221204943](img/SpringSecurity学习笔记/image-20220731221204943.png)





```java

package org.springframework.security.crypto.bcrypt;

import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Implementation of PasswordEncoder that uses the BCrypt strong hashing function. Clients
 * can optionally supply a "version" ($2a, $2b, $2y) and a "strength" (a.k.a. log rounds
 * in BCrypt) and a SecureRandom instance. The larger the strength parameter the more work
 * will have to be done (exponentially) to hash the passwords. The default value is 10.
 *
 * @author Dave Syer
 */
public class BCryptPasswordEncoder implements PasswordEncoder {

   private Pattern BCRYPT_PATTERN = Pattern.compile("\\A\\$2(a|y|b)?\\$(\\d\\d)\\$[./0-9A-Za-z]{53}");

   private final Log logger = LogFactory.getLog(getClass());

   private final int strength;

   private final BCryptVersion version;

   private final SecureRandom random;

   public BCryptPasswordEncoder() {
      this(-1);
   }

   /**
    * @param strength the log rounds to use, between 4 and 31
    */
   public BCryptPasswordEncoder(int strength) {
      this(strength, null);
   }

   /**
    * @param version the version of bcrypt, can be 2a,2b,2y
    */
   public BCryptPasswordEncoder(BCryptVersion version) {
      this(version, null);
   }

   /**
    * @param version the version of bcrypt, can be 2a,2b,2y
    * @param random the secure random instance to use
    */
   public BCryptPasswordEncoder(BCryptVersion version, SecureRandom random) {
      this(version, -1, random);
   }

   /**
    * @param strength the log rounds to use, between 4 and 31
    * @param random the secure random instance to use
    */
   public BCryptPasswordEncoder(int strength, SecureRandom random) {
      this(BCryptVersion.$2A, strength, random);
   }

   /**
    * @param version the version of bcrypt, can be 2a,2b,2y
    * @param strength the log rounds to use, between 4 and 31
    */
   public BCryptPasswordEncoder(BCryptVersion version, int strength) {
      this(version, strength, null);
   }

   /**
    * @param version the version of bcrypt, can be 2a,2b,2y
    * @param strength the log rounds to use, between 4 and 31
    * @param random the secure random instance to use
    */
   public BCryptPasswordEncoder(BCryptVersion version, int strength, SecureRandom random) {
      if (strength != -1 && (strength < BCrypt.MIN_LOG_ROUNDS || strength > BCrypt.MAX_LOG_ROUNDS)) {
         throw new IllegalArgumentException("Bad strength");
      }
      this.version = version;
      this.strength = (strength == -1) ? 10 : strength;
      this.random = random;
   }

   @Override
   public String encode(CharSequence rawPassword) {
      if (rawPassword == null) {
         throw new IllegalArgumentException("rawPassword cannot be null");
      }
      String salt = getSalt();
      return BCrypt.hashpw(rawPassword.toString(), salt);
   }

   private String getSalt() {
      if (this.random != null) {
         return BCrypt.gensalt(this.version.getVersion(), this.strength, this.random);
      }
      return BCrypt.gensalt(this.version.getVersion(), this.strength);
   }

   @Override
   public boolean matches(CharSequence rawPassword, String encodedPassword) {
      if (rawPassword == null) {
         throw new IllegalArgumentException("rawPassword cannot be null");
      }
      if (encodedPassword == null || encodedPassword.length() == 0) {
         this.logger.warn("Empty encoded password");
         return false;
      }
      if (!this.BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
         this.logger.warn("Encoded password does not look like BCrypt");
         return false;
      }
      return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
   }

   @Override
   public boolean upgradeEncoding(String encodedPassword) {
      if (encodedPassword == null || encodedPassword.length() == 0) {
         this.logger.warn("Empty encoded password");
         return false;
      }
      Matcher matcher = this.BCRYPT_PATTERN.matcher(encodedPassword);
      if (!matcher.matches()) {
         throw new IllegalArgumentException("Encoded password does not look like BCrypt: " + encodedPassword);
      }
      int strength = Integer.parseInt(matcher.group(2));
      return strength < this.strength;
   }

   /**
    * Stores the default bcrypt version for use in configuration.
    *
    * @author Lin Feng
    */
   public enum BCryptVersion {

      $2A("$2a"),

      $2Y("$2y"),

      $2B("$2b");

      private final String version;

      BCryptVersion(String version) {
         this.version = version;
      }

      public String getVersion() {
         return this.version;
      }

   }

}
```





测试



```java
package mao.springsecurity_demo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class SpringSecurityDemoApplicationTests
{

    @Test
    void contextLoads()
    {
    }

    @Test
    void testBCryptPasswordEncoder()
    {
        BCryptPasswordEncoder bCryptPasswordEncoder=new BCryptPasswordEncoder();
        String encode = bCryptPasswordEncoder.encode("123");
        System.out.println(encode);
        System.out.println(encode.length());
        System.out.println(bCryptPasswordEncoder.encode("saks"));
        System.out.println(bCryptPasswordEncoder.encode("123456789"));
        System.out.println(bCryptPasswordEncoder.matches("123",encode));
        System.out.println(bCryptPasswordEncoder.matches("124",encode));
        System.out.println(bCryptPasswordEncoder.matches("1123",encode));
    }
}

```





测试结果：

```sh
$2a$10$l2nW7ut0ThVV4fA1QeKR6eP6rPFqT.KUUNIp2LS6m3HEyeP9XAgNq
60
$2a$10$NXwYkEFRJ6PnF1iKT1yOiec2BjTSO2X.opMezz2hxzb06yUycCsmm
$2a$10$qd9Cov2lEj8RmrCo7wVoZOezCWFxR8ShtrYCdMe2LpTi.OWR3eWCy
true
false
false
```



第二次运行：

```sh
$2a$10$vNKzVK6cW2m2vv8vAPocwuMIBIHp6JHJZ8qzYp11PK8.U7c.4d0pS
60
$2a$10$yVqAF1MHyemO6vFTiZM66O/mKBzASOxl9Jh8oZ1.34GF0AQTiGli.
$2a$10$dO3cdl5Ce7op.qm9xAce1.Uh7Mmnzq3h1abW.t1lHyEgRRwZEEKme
true
false
false
```



更改代码：

```java
package mao.springsecurity_demo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class SpringSecurityDemoApplicationTests
{

    @Test
    void contextLoads()
    {
    }

    @Test
    void testBCryptPasswordEncoder()
    {
        BCryptPasswordEncoder bCryptPasswordEncoder=new BCryptPasswordEncoder();
        String encode = bCryptPasswordEncoder.encode("123");
        System.out.println(encode);
        System.out.println(encode.length());
        System.out.println(bCryptPasswordEncoder.encode("saks"));
        System.out.println(bCryptPasswordEncoder.encode("123456789"));
        System.out.println(bCryptPasswordEncoder.matches("123",encode));
        System.out.println(bCryptPasswordEncoder.matches("124",encode));
        System.out.println(bCryptPasswordEncoder.matches("1123",encode));
        System.out.println(bCryptPasswordEncoder.matches("123","$2a$10$l2nW7ut0ThVV4fA1QeKR6eP6rPFqT.KUUNIp2LS6m3HEyeP9XAgNq"));
    }
}
```



运行：

```sh
$2a$10$ZHcX4sqcWKL8WcSpxcpZH.zcW0r26pBh8MrL4xUTV.0tQ3JziL1eS
60
$2a$10$69x/IOu3B4zFFCBHOzk64eCxeuixb.nZqlgLmiGLBcn/2vgw7gtqm
$2a$10$pQDk9/AR.jMi5Gv6eUF/KugZMOTiUc9QqdZtQXeID.SWcTFedFsB.
true
false
false
true
```



在使用穷举法暴力破解中，md5算法生成一个密文用时在微秒级，也就是说，一个6位密码的所有组合，通过穷举只需要40秒。

而使用bcrypt算法，生成一个密文用时在毫秒级，通过穷举法，需要用上好几年的时间才能列举所有可能值。

在SpringSecurity 3.0版本中，可以使用md5进行加密，但到了5.0版本，官方提倡使用bcrypt，不再提供md5算法加密，如需必要，需人工导入Md5算法的工具类。









# 设置登录系统的账号和密码





## 方法一



在配置文件里声明



```yaml
spring:
  security:
    user:
      name: abc
      password: 123456
```





```yaml

#多环境开发---单文件
spring:
  profiles:
    # 当前环境
    active: dev

#-----通用环境---------------------------------------------------------

  # 导入jdbc.properties文件
#  config:
#    import: classpath:jdbc.properties


  #spring-mvc配置
  mvc:
    # 视图解析器
    view:
      prefix:
      suffix: .html



  security:
    user:
      name: abc
      password: 123456





---
#------开发环境--------------------------------------------------------

spring:
  config:
    activate:
      on-profile: dev

#  # 配置数据源
#  datasource:
#    # driver-class-name: ${jdbc.driver}
#    # url: ${jdbc.url}
#    # username: ${jdbc.username}
#    # password: ${jdbc.password}
#    # 配置数据源-druid
#    druid:
#      driver-class-name: ${jdbc.driver}
#      url: ${jdbc.url}
#      username: ${jdbc.username}
#      password: ${jdbc.password}







# 开启debug模式，输出调试信息，常用于检查系统运行状况
#debug: true

# 设置日志级别，root表示根节点，即整体应用日志级别
logging:
 # 日志输出到文件的文件名
  file:
     name: server.log
  # 字符集
  charset:
    file: UTF-8
  # 分文件
  logback:
    rollingpolicy:
      #最大文件大小
      max-file-size: 16KB
      # 文件格式
      file-name-pattern: logs/server_log-%d{yyyy/MM月/dd日/}%i.log
  # 设置日志组
  group:
  # 自定义组名，设置当前组中所包含的包
    mao_pro: mao
  level:
    root: info
    # 为对应组设置日志级别
    mao_pro: debug
    # 日志输出格式
# pattern:
  # console: "%d %clr(%p) --- [%16t] %clr(%-40.40c){cyan} : %m %n"




---
#----生产环境----------------------------------------------------


spring:
  config:
    activate:
      on-profile: pro






---
#----测试环境-----------------------------------------------------

spring:
  config:
    activate:
      on-profile: test

```





访问：

http://localhost:8080/



![image-20220731233624443](img/SpringSecurity学习笔记/image-20220731233624443.png)



![image-20220731233654893](img/SpringSecurity学习笔记/image-20220731233654893.png)





![image-20220731233829873](img/SpringSecurity学习笔记/image-20220731233829873.png)



认证成功







## 方法二



编写类实现接口



实现UserDetailsService

```java
package mao.springsecurity_demo.service;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): LoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/31
 * Time(创建时间)： 23:41
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class LoginService implements UserDetailsService
{

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        //判断用户名是否为abc
        if (!username.equals("abc"))
        {
            throw new UsernameNotFoundException("用户不存在！");
        }
        //设置abcd的密码，原密码为123
        String password = "$2a$10$ZHcX4sqcWKL8WcSpxcpZH.zcW0r26pBh8MrL4xUTV.0tQ3JziL1eS";
        return new User(username, password, AuthorityUtils.commaSeparatedStringToAuthorityList("admin,"));
    }
}
```



配置密码转换器

```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录
        http.formLogin()
                .and()
                //认证配置
                .authorizeRequests()
                //如何请求都需要身份认证
                .anyRequest().authenticated();

    }


    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

}
```





访问：

http://localhost:8080/



用户名为abc

密码为123







# 基于数据库认证实现用户登录





## 准备sql



```sql
/*
 Navicat MySQL Data Transfer

 Source Server         : localhost_3306
 Source Server Type    : MySQL
 Source Server Version : 80027
 Source Host           : localhost:3306
 Source Schema         : student1

 Target Server Type    : MySQL
 Target Server Version : 80027
 File Encoding         : 65001

 Date: 01/08/2022 00:12:06
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for administrators
-- ----------------------------
DROP TABLE IF EXISTS `administrators`;
CREATE TABLE `administrators`  (
  `administrator_no` bigint NOT NULL COMMENT '管理员编号',
  `administrator_name` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '管理员姓名',
  `administrator_sex` varchar(4) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '管理员性别',
  `administrator_telephone_number` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '管理员手机号码',
  `administrator_job` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '管理员职务',
  `administrator_idcard` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '管理员身份证号码',
  PRIMARY KEY (`administrator_no`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of administrators
-- ----------------------------
INSERT INTO `administrators` VALUES (10001, '唐淑玲', '女', '13801143638', '校长', '439165200008274998');
INSERT INTO `administrators` VALUES (10002, '隗瑶', '女', '15302990518', '副校长', '422080200209084877');
INSERT INTO `administrators` VALUES (10003, '甫黛', '女', '13204546288', '副校长', '435943200304212416');
INSERT INTO `administrators` VALUES (10004, '祖瑶影', '女', '13606453515', '计算机学院院长', '437336199902254962');
INSERT INTO `administrators` VALUES (10005, '裴策奇', '男', '13906801424', '计算机学院副院长', '436700200205167159');
INSERT INTO `administrators` VALUES (10006, '常新', '男', '15200884859', '计算机学院副院长', '425230199905174567');
INSERT INTO `administrators` VALUES (10007, '文波', '男', '13002966149', '计算机学院副院长', '440405199901072724');
INSERT INTO `administrators` VALUES (10008, '牛巧', '女', '15906467901', '管理员', '427804200109122721');
INSERT INTO `administrators` VALUES (10009, '琴有奇', '男', '13207633407', '管理员', '437776200107198012');
INSERT INTO `administrators` VALUES (10010, '容彪诚', '男', '13704933439', '管理员', '435874200305254814');
INSERT INTO `administrators` VALUES (10011, '酆馥霞', '女', '13805661106', '管理员', '432958199903241775');
INSERT INTO `administrators` VALUES (10012, '仇生良', '男', '13204292788', '管理员', '422574200108068146');
INSERT INTO `administrators` VALUES (10013, '蒙海冠', '男', '13003853784', '管理员', '423806200205164383');
INSERT INTO `administrators` VALUES (10014, '贡瑾育', '女', '13800310215', '管理员', '436145200003095722');
INSERT INTO `administrators` VALUES (10015, '钟园璐', '女', '15204391113', '管理员', '431764199909143390');
INSERT INTO `administrators` VALUES (10016, '向冠', '男', '15005897305', '管理员', '430461200304265635');
INSERT INTO `administrators` VALUES (10017, '彭辉生', '男', '13700370300', '管理员', '432611200105216186');
INSERT INTO `administrators` VALUES (10018, '常荣芝', '女', '13704638779', '管理员', '422857200104226262');
INSERT INTO `administrators` VALUES (10019, '李明', '男', '13804178399', '管理员', '434880200009014080');
INSERT INTO `administrators` VALUES (10020, '白鸣坚', '男', '15601790970', '管理员', '428468199903043027');
INSERT INTO `administrators` VALUES (10021, '富凝珠', '女', '13002418313', '管理员', '427292200111188298');
INSERT INTO `administrators` VALUES (10022, '宰广震', '男', '13306854395', '管理员', '435022200307255751');
INSERT INTO `administrators` VALUES (10023, '曾奇利', '男', '13503052929', '管理员', '431917200309113634');
INSERT INTO `administrators` VALUES (10024, '离良光', '男', '13205957069', '管理员', '427136200309201542');
INSERT INTO `administrators` VALUES (10025, '都德光', '男', '13908498869', '管理员', '427667200102066356');
INSERT INTO `administrators` VALUES (10026, '终泰', '男', '13402995699', '管理员', '421738200201021058');
INSERT INTO `administrators` VALUES (10027, '乐振', '男', '13802950621', '管理员', '432185200103143063');
INSERT INTO `administrators` VALUES (10028, '百咏眉', '女', '15900848912', '管理员', '432945200311205420');
INSERT INTO `administrators` VALUES (10029, '益育', '女', '13003655837', '管理员', '431957200302288367');
INSERT INTO `administrators` VALUES (10030, '姓岚玲', '女', '15500945048', '管理员', '427975200306115062');

SET FOREIGN_KEY_CHECKS = 1;
```





```sql
/*
 Navicat MySQL Data Transfer

 Source Server         : localhost_3306
 Source Server Type    : MySQL
 Source Server Version : 80027
 Source Host           : localhost:3306
 Source Schema         : student1

 Target Server Type    : MySQL
 Target Server Version : 80027
 File Encoding         : 65001

 Date: 01/08/2022 00:12:42
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for administrators_password
-- ----------------------------
DROP TABLE IF EXISTS `administrators_password`;
CREATE TABLE `administrators_password`  (
  `administrator_no` bigint NOT NULL COMMENT '管理员编号',
  `administrator_password` varchar(130) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '管理员密码，散列值',
  INDEX `administrator_no`(`administrator_no`) USING BTREE,
  CONSTRAINT `administrator_no` FOREIGN KEY (`administrator_no`) REFERENCES `administrators` (`administrator_no`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of administrators_password
-- ----------------------------
INSERT INTO `administrators_password` VALUES (10001, 'f6f701b41d908b621f711bb85b153e4bdf28563c5d9a4cc8658ea551e2b656d23fd21cc634dcc578719333ae549d6fd3fb1619fe9672fae2733eb6e1cec536a5');
INSERT INTO `administrators_password` VALUES (10002, 'f6f701b41d908b621f711bb85b153e4bdf28563c5d9a4cc8658ea551e2b656d23fd21cc634dcc578719333ae549d6fd3fb1619fe9672fae2733eb6e1cec536a5');
INSERT INTO `administrators_password` VALUES (10003, '527e2b092a7aafb298358a84847ac48ead7ffe512f9b60a17e36bdf4a3121c3ee11e848badbfe4f81ef5708cf63256096a3de4b4dc3735f8e1ea5a2c8c834987');
INSERT INTO `administrators_password` VALUES (10004, '66e7d009807bc5672fa1260f367486431b0d78b0c7439c566a2ce52c37c5dae98b3649bdb9958852e46a94f8dfc2da0872aa74cc99eb97d5d1b38ae94cdb3501');
INSERT INTO `administrators_password` VALUES (10005, 'a603d6300e74b6df96c29d856e9f17dd398d62c3396f5a83b41f388dc4de63b89eb3ba499dac92ec9f02ccabad0c5d715913a83e2a5fc22acd1de0620323a6c5');
INSERT INTO `administrators_password` VALUES (10006, '5737864d4aee7f6337a8d00dfea3a9455f9124cacef194e2d8445cc0fb408d8efbf6e6b3d244448d100dcd04218b4721781c6343bfaceb084f35de74f4050509');
INSERT INTO `administrators_password` VALUES (10007, 'dede253f18a5f01334d13519d0d331bf3775560be18893ecf011a250672f30bc9a1b00e9c0b94cf27312c59f3fdb94d7d5bf00e32b23e0b0273a0526e81b1d3d');
INSERT INTO `administrators_password` VALUES (10008, '355fcef1e85f8dc5cbb875dcd2859059e17b65762b1f86d16a99659329dfe2326f9afe788da3673689754f90ffe87566b9aa74a5d116126b18d54c422209d8ff');
INSERT INTO `administrators_password` VALUES (10009, 'b65d52ea5045886f97d4a68329159c6551d182a1b0fda2b23ee856f3a4b24400a08f18373e394bc80aad15c473f5b6af526322da77105ce587bf14ae9876800c');
INSERT INTO `administrators_password` VALUES (10010, '97d0455eb959748dcc06436f8c07f0a735560a82af2f2bf119d7afbcc9c017b925d6048a11ae995dbcae21709233e9519ef05e5250cd0e8510b64ed130512d67');
INSERT INTO `administrators_password` VALUES (10011, 'dca2cf36b39f366b246e63b33564e0709ecb11cad206cde76b1e0d36e4aaeed7863abc7bb61cbb86af1fd09c01c73bbe8e482cf7f90316254f23b8de53a2ce88');
INSERT INTO `administrators_password` VALUES (10012, '6801a4b78b320392b22650557316f733461fbafd696cc704e71b3b70a409c4afd215fe4dc1fd8e1e614c3fa0306bc081fa662a0347d14c39fd33bf856f34e424');
INSERT INTO `administrators_password` VALUES (10013, 'd9594e70d32751fd3854ec52f057bf3d76aa23a38bed17fd42257f6d6a9188af902ffaa326da693af3b47d9c2303065a1e7e3e2fcc92644956a719cefbc5c8dc');
INSERT INTO `administrators_password` VALUES (10014, '8da5ad3b9b2a6bee9eea4855c8e0293280ebe8f8ef4b45fccb9e44c538b07b699e12d4eab969de838e3bb938c782c34f2be598d2a6e0270bb96f171ac3d8f595');
INSERT INTO `administrators_password` VALUES (10015, '96a0b69c0b96e64f1b4488e8bfc211be6884be0175798783fab4f877dfa9b615c8e045cffb1665ce764f4cd6ff8c649fd5952780c127be64435f2a461eb3459f');
INSERT INTO `administrators_password` VALUES (10016, '6366050392ddcaef89ee152bb155a24a64df704b665bc2690ae9b16e2746c12714424230a2800567ba16aeffce7dddb59bca6b7973881ac1dc3065f2123ec3cd');
INSERT INTO `administrators_password` VALUES (10017, '47c5c3fd98b0a8db01ddc3bec5dca96a0b1d080dff9d355e22e3d7e1968aeaaa47e82ebc21a97c6569816b07f541647330e5d6a69efc20a9a872352bbc610eb5');
INSERT INTO `administrators_password` VALUES (10018, '61a57773a2f598a7093376e92947148660c40c2af70ad380c041e5ee9806289e25ae32f393d15b6bf9420058a084d35a14dbefb07cca6d35eabc88367eefed68');
INSERT INTO `administrators_password` VALUES (10019, '351e53506ed3d25a88eeee2e23663d8def008d80f21fd68703f4258b716b1269986cd35c6cbe82ffa0242d47f216f9dff5e9bd7e855cc763fa1754da1f24e9e5');
INSERT INTO `administrators_password` VALUES (10020, 'fcb6173c708d343531ae02b7ec15c13b433eed9be37dcfa62feb6116082489cd19202447488d985f74dc16ed1817bd406ae722bcbea7bc085beb1b5a8ab6c1cc');
INSERT INTO `administrators_password` VALUES (10021, '2e59b1040a14da3fc257d8f2403d1eeb487e6191acc0b5d8c467cf8061900cde60285201d8259db159a30cd5814f3129c38629a3af641d8e8588d4261c09dc93');
INSERT INTO `administrators_password` VALUES (10022, 'c1420b70768099d81b1c738a531c47accd58c951d59f1703ff90d0d7c6936adca4c1b7eb6d6683a75b822df90279d55e06b1b28b868a1d67eea036aa760f0814');
INSERT INTO `administrators_password` VALUES (10023, 'ee4117b3661b6c9de71d118bb2b6d1d35ce6830f78cc76cc0419e974677902f40d4d08accb1b658f77396c0ca57f2d5b89e03a456bd7b19bef9960f5484f1163');
INSERT INTO `administrators_password` VALUES (10024, '7797155d0e5a391d9e0c9f52c213665a8389d3feaf85088215c06cb422c142fe06328eb94284ad25ffa1a835cf46a4afaea6fc99f1c44a741fbf05873af45269');
INSERT INTO `administrators_password` VALUES (10025, '9854bed4cc960b727014383b5bcd3f5bb5ed89a204d3e397f7d55a0d28baabb5e7e42b6cbb5a5bb1ef4bd233633f099957752d7d4584dfce9e5860fc44126125');
INSERT INTO `administrators_password` VALUES (10026, '1633c429d84041a2d58f16f122a3291672d6d717dc2e34fb81adb74974f59901ab463b3c42c86ef8ff69bb2f0c435fce57f628879d804352415612f541ec2693');
INSERT INTO `administrators_password` VALUES (10027, 'dce96367f3a26eddcc738cab52347e90e1c6ca2570f8828bdf018720c3ac80be4d026fb37397ddab808c4379dfa04a81bce440e1e87b1fb7b3e1e8be7247500a');
INSERT INTO `administrators_password` VALUES (10028, '260b49fdc931debae66ab2b1e5dbe13f207f9dfe1adf3ccfc4befee3ed6cd460105a1786b3e4a57691fe8d84ac1b42fa36c11a90b0b2043005faaf209e7d2886');
INSERT INTO `administrators_password` VALUES (10029, '89e02ead289a62bbecff5090127816339d23b58f4a9ff5b7777e5428a63b05d747e9c8d49ec4b362a8c6b9f7753648124054beb5303641951c6df654e9ca0f5e');
INSERT INTO `administrators_password` VALUES (10030, '9cb2e38b9060c99614dceb52841fb798f8dbdc8c6d4a11cb3e5e07778318972b8f9815156c84925c01e535d1d468b0985e608316f82247cd32cfcf4ccd18946c');

SET FOREIGN_KEY_CHECKS = 1;
```





加密算法为sha3_512

密码默认为身份证后六位，部分已更改





## 更改pom文件



```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.2</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>mao</groupId>
    <artifactId>springSecurity_demo</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>springSecurity_demo</name>
    <description>springSecurity_demo</description>
    <properties>
        <java.version>11</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!-- spring security 安全框架依赖 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <!-- spring security 安全框架测试依赖 -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!--mysql依赖 spring-boot-->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.27</version>
            <scope>runtime</scope>
        </dependency>

        <!--spring-boot druid连接池依赖-->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid-spring-boot-starter</artifactId>
            <version>1.2.8</version>
        </dependency>

        <!--spring-boot mybatis-plus依赖-->
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.5.1</version>
        </dependency>

        <!--mybatis-plus代码生成器-->
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-generator</artifactId>
            <version>3.5.1</version>
        </dependency>
        <!-- 模板引擎 默认 -->
        <dependency>
            <groupId>org.apache.velocity</groupId>
            <artifactId>velocity-engine-core</artifactId>
            <version>2.3</version>
        </dependency>
        <!--swagger-->
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-swagger2</artifactId>
            <version>2.7.0</version>
        </dependency>

    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>

```





## jdbc.properties

```properties
#驱动
jdbc.driver=com.mysql.cj.jdbc.Driver
#url
jdbc.url=jdbc:mysql://localhost:3306/student1
#用户名
jdbc.username=root
#密码
jdbc.password=20010713
```





## 代码生成类



```java
package mao.springsecurity_demo;

import com.baomidou.mybatisplus.generator.FastAutoGenerator;
import com.baomidou.mybatisplus.generator.config.OutputFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Properties;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo
 * Class(类名): MybatisPlusSqlGenerator
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 13:26
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public class MybatisPlusSqlGenerator
{
public static void main(String[] args) throws IOException
    {
        /*
        //旧
        // 1、创建代码生成器
        AutoGenerator autoGenerator = new AutoGenerator();

        // 2、全局配置
        GlobalConfig globalConfig = new GlobalConfig();
        String projectPath = System.getProperty("user.dir");
        // 项目输出根目录
        globalConfig.setOutputDir(projectPath + "/src/main/java");
        // 作者
        globalConfig.setAuthor("mao");
        //生成后是否打开资源管理器
        globalConfig.setOpen(false);
        //去掉Service接口的首字母I
        globalConfig.setServiceName("%sService");
        //主键策略
        globalConfig.setIdType(IdType.AUTO);
        //开启Swagger2模式
        globalConfig.setSwagger2(true);
        autoGenerator.setGlobalConfig(globalConfig);

        // 3、数据源配置
        InputStream inputStream = MybatisPlusSqlGenerator.class.getClassLoader().getResourceAsStream("jdbc.properties");
        Properties properties=new Properties();
        properties.load(inputStream);
        DataSourceConfig dataSourceConfig = new DataSourceConfig();
        dataSourceConfig.setUrl(properties.getProperty("jdbc.url"));
        dataSourceConfig.setDriverName(properties.getProperty("jdbc.driver"));
        dataSourceConfig.setUsername(properties.getProperty("jdbc.username"));
        dataSourceConfig.setPassword(properties.getProperty("jdbc.password"));
        //设置方言
        dataSourceConfig.setDbType(DbType.MYSQL);
        autoGenerator.setDataSource(dataSourceConfig);

        // 4、包配置
        PackageConfig packageConfig = new PackageConfig();
        // 生成的文件放在那个目录下  若没有该文件 则会创建
        packageConfig.setParent("com.alibaba.product");
        //此对象与数据库表结构一一对应，通过 DAO 层向上传输数据源对象。
        packageConfig.setEntity("pojo.entity");
        autoGenerator.setPackageInfo(packageConfig);

        // 5、策略配置
        StrategyConfig strategy = new StrategyConfig();
        //数据库表映射到实体的命名策略
        strategy.setNaming(NamingStrategy.underline_to_camel);
        //数据库表字段映射到实体的命名策略
        strategy.setColumnNaming(NamingStrategy.underline_to_camel);
        // lombok
        strategy.setEntityLombokModel(false);
        //逻辑删除字段名
        strategy.setLogicDeleteFieldName("is_deleted");
        //去掉布尔值的is_前缀（确保tinyint(1)）
        strategy.setEntityBooleanColumnRemoveIsPrefix(true);
        //restful api风格控制器
        strategy.setRestControllerStyle(true);
        autoGenerator.setStrategy(strategy);

        // 6、执行
        autoGenerator.execute();
        */

        //新
        InputStream inputStream = MybatisPlusSqlGenerator.class.getClassLoader().getResourceAsStream("jdbc.properties");
        Properties properties=new Properties();
        properties.load(inputStream);
        FastAutoGenerator.create(properties.getProperty("jdbc.url"),
                        properties.getProperty("jdbc.username"),
                        properties.getProperty("jdbc.password"))
                .globalConfig(builder ->
                {
                    builder.author("mao") // 设置作者
                            .enableSwagger() // 开启 swagger 模式
                            //.fileOverride() // 覆盖已生成文件
                            .outputDir("src\\main\\java"); // 指定输出目录
                })
                .packageConfig(builder ->
                {
                    builder.parent("mao.springsecurity_demo") // 设置父包名
                            //.moduleName("system") // 设置父包模块名
                            .pathInfo(Collections.singletonMap(OutputFile.mapperXml, "src\\main\\resources\\mapper")); // 设置mapperXml生成路径
                })
                .strategyConfig(builder ->
                {
                    builder.addInclude("administrators"); // 设置需要生成的表名
                    builder.addInclude("administrators_password");
                            //.addTablePrefix("t_", "c_"); // 设置过滤表前缀
                })
                //.templateEngine(new FreemarkerTemplateEngine()) // 使用Freemarker引擎模板，默认的是Velocity引擎模板
                .execute();
    }
}
```





## 运行



```sh
13:30:31.087 [main] DEBUG com.baomidou.mybatisplus.generator.AutoGenerator - ==========================准备生成文件...==========================
13:30:31.109 [main] WARN org.apache.velocity.deprecation - configuration key 'file.resource.loader.class' has been deprecated in favor of 'resource.loader.file.class'
13:30:31.110 [main] WARN org.apache.velocity.deprecation - configuration key 'file.resource.loader.unicode' has been deprecated in favor of 'resource.loader.file.unicode'
13:30:31.654 [main] DEBUG com.baomidou.mybatisplus.generator.config.querys.MySqlQuery - 执行SQL:show table status WHERE 1=1  AND NAME IN ('administrators_password','administrators')
13:30:31.696 [main] DEBUG com.baomidou.mybatisplus.generator.config.querys.MySqlQuery - 返回记录数:2,耗时(ms):41
13:30:31.720 [main] DEBUG com.baomidou.mybatisplus.generator.config.querys.MySqlQuery - 执行SQL:show full fields from `administrators`
13:30:31.730 [main] DEBUG com.baomidou.mybatisplus.generator.config.querys.MySqlQuery - 返回记录数:6,耗时(ms):10
13:30:31.744 [main] DEBUG com.baomidou.mybatisplus.generator.config.querys.MySqlQuery - 执行SQL:show full fields from `administrators_password`
13:30:31.748 [main] DEBUG com.baomidou.mybatisplus.generator.config.querys.MySqlQuery - 返回记录数:2,耗时(ms):4
13:30:31.756 [main] DEBUG org.apache.velocity - Initializing Velocity, Calling init()...
13:30:31.756 [main] DEBUG org.apache.velocity - Starting Apache Velocity v2.3
13:30:31.759 [main] DEBUG org.apache.velocity - Default Properties resource: org/apache/velocity/runtime/defaults/velocity.properties
13:30:31.769 [main] DEBUG org.apache.velocity - ResourceLoader instantiated: org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.770 [main] DEBUG org.apache.velocity - initialized (class org.apache.velocity.runtime.resource.ResourceCacheImpl) with class java.util.Collections$SynchronizedMap cache map.
13:30:31.771 [main] DEBUG org.apache.velocity - Loaded System Directive: org.apache.velocity.runtime.directive.Stop
13:30:31.772 [main] DEBUG org.apache.velocity - Loaded System Directive: org.apache.velocity.runtime.directive.Define
13:30:31.772 [main] DEBUG org.apache.velocity - Loaded System Directive: org.apache.velocity.runtime.directive.Break
13:30:31.773 [main] DEBUG org.apache.velocity - Loaded System Directive: org.apache.velocity.runtime.directive.Evaluate
13:30:31.773 [main] DEBUG org.apache.velocity - Loaded System Directive: org.apache.velocity.runtime.directive.Macro
13:30:31.774 [main] DEBUG org.apache.velocity - Loaded System Directive: org.apache.velocity.runtime.directive.Parse
13:30:31.775 [main] DEBUG org.apache.velocity - Loaded System Directive: org.apache.velocity.runtime.directive.Include
13:30:31.775 [main] DEBUG org.apache.velocity - Loaded System Directive: org.apache.velocity.runtime.directive.Foreach
13:30:31.790 [main] DEBUG org.apache.velocity.parser - Created '20' parsers.
13:30:31.805 [main] DEBUG org.apache.velocity.macro - "velocimacro.library.path" is not set. Trying default library: velocimacros.vtl
13:30:31.806 [main] DEBUG org.apache.velocity.loader.file - Could not load resource 'velocimacros.vtl' from ResourceLoader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.806 [main] DEBUG org.apache.velocity.macro - Default library velocimacros.vtl not found. Trying old default library: VM_global_library.vm
13:30:31.806 [main] DEBUG org.apache.velocity.loader.file - Could not load resource 'VM_global_library.vm' from ResourceLoader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.806 [main] DEBUG org.apache.velocity.macro - Old default library VM_global_library.vm not found.
13:30:31.806 [main] DEBUG org.apache.velocity.macro - allowInline = true: VMs can be defined inline in templates
13:30:31.806 [main] DEBUG org.apache.velocity.macro - allowInlineToOverride = false: VMs defined inline may NOT replace previous VM definitions
13:30:31.806 [main] DEBUG org.apache.velocity.macro - allowInlineLocal = false: VMs defined inline will be global in scope if allowed.
13:30:31.806 [main] DEBUG org.apache.velocity.macro - autoload off: VM system will not automatically reload global library macros
13:30:31.829 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/entity.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.850 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/mapper.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.855 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/mapper.xml.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.858 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/service.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.862 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/serviceImpl.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.867 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/controller.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.875 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/entity.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.882 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/mapper.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.887 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/mapper.xml.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.889 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/service.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.891 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/serviceImpl.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.894 [main] DEBUG org.apache.velocity.loader - ResourceManager: found /templates/controller.java.vm with loader org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
13:30:31.908 [main] DEBUG com.baomidou.mybatisplus.generator.AutoGenerator - ==========================文件生成完成！！！==========================

进程已结束，退出代码为 0
```





## 更改配置文件



```yaml
#多环境开发---单文件
spring:
  profiles:
    # 当前环境
    active: dev

#-----通用环境---------------------------------------------------------

  # 导入jdbc.properties文件
  config:
    import: classpath:jdbc.properties






#  security:
#    user:
#      name: abc
#      password: 123456






---
#------开发环境--------------------------------------------------------

spring:
  config:
    activate:
      on-profile: dev

  # 配置数据源
  datasource:
    # driver-class-name: ${jdbc.driver}
    # url: ${jdbc.url}
    # username: ${jdbc.username}
    # password: ${jdbc.password}
    # 配置数据源-druid
    druid:
      driver-class-name: ${jdbc.driver}
      url: ${jdbc.url}
      username: ${jdbc.username}
      password: ${jdbc.password}







# 开启debug模式，输出调试信息，常用于检查系统运行状况
#debug: true

# 设置日志级别，root表示根节点，即整体应用日志级别
logging:
 # 日志输出到文件的文件名
  file:
     name: server.log
  # 字符集
  charset:
    file: UTF-8
  # 分文件
  logback:
    rollingpolicy:
      #最大文件大小
      max-file-size: 16KB
      # 文件格式
      file-name-pattern: logs/server_log-%d{yyyy/MM月/dd日/}%i.log
  # 设置日志组
  group:
  # 自定义组名，设置当前组中所包含的包
    mao_pro: mao
  level:
    root: info
    # 为对应组设置日志级别
    mao_pro: debug
    # 日志输出格式
# pattern:
  # console: "%d %clr(%p) --- [%16t] %clr(%-40.40c){cyan} : %m %n"




---
#----生产环境----------------------------------------------------


spring:
  config:
    activate:
      on-profile: pro






---
#----测试环境-----------------------------------------------------

spring:
  config:
    activate:
      on-profile: test
```





## 注释掉passwordEncoder的bean



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录
        http.formLogin()
                .and()
                //认证配置
                .authorizeRequests()
                //如何请求都需要身份认证
                .anyRequest().authenticated();

    }


//    @Bean
//    public PasswordEncoder passwordEncoder()
//    {
//        return new BCryptPasswordEncoder();
//    }

}
```





## SHA3_512类



```java
package mao.springsecurity_demo.sha;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.sha
 * Class(类名): SHA3_512
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 0:19
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public class SHA3_512
{
    private static String SHA(final String strText)
    {
        String strResult = null;
        if (strText != null && strText.length() > 0)
        {
            try
            {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
                messageDigest.update(strText.getBytes());
                byte[] byteBuffer = messageDigest.digest();
                StringBuilder strHexString = new StringBuilder();
                for (int i = 0; i < byteBuffer.length; i++)
                {
                    String hex = Integer.toHexString(0xff & byteBuffer[i]);
                    if (hex.length() == 1)
                    {
                        strHexString.append('0');
                    }
                    strHexString.append(hex);
                }
                strResult = strHexString.toString();
            }
            catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }
        }
        return strResult;
    }

    public static String getSHA3_512(String strText)
    {
        return SHA(strText);
    }

    public static String getSHA3_512toUpperCase(String strText)
    {
        return SHA(strText).toUpperCase();
    }
}
```





## SHA3_512PasswordEncoder类



```java
package mao.springsecurity_demo.passwordEncoder;

import mao.springsecurity_demo.sha.SHA3_512;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.passwordEncoder
 * Class(类名): SHA3_512PasswordEncoder
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 0:18
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Component
public class SHA3_512PasswordEncoder implements PasswordEncoder
{

    @Override
    public String encode(CharSequence rawPassword)
    {
        return SHA3_512.getSHA3_512(rawPassword.toString());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword)
    {
        return SHA3_512.getSHA3_512(rawPassword.toString()).equals(encodedPassword);
    }
}
```





## 注释的掉LoginService类上的注解@Service





## AdministratorsLoginService类



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                AuthorityUtils.createAuthorityList("administrator"));
    }
}
```





## TestController类



```java
package mao.springsecurity_demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:52
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@RestController
@RequestMapping("/test")
public class TestController
{
    @GetMapping("")
    public String success()
    {
        return "success";
    }

}
```





## 启动服务



```sh
OpenJDK 64-Bit Server VM warning: Options -Xverify:none and -noverify were deprecated in JDK 13 and will likely be removed in a future release.

  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::                (v2.7.2)

2022-08-01 14:58:01.438  INFO 15684 --- [           main] m.s.SpringSecurityDemoApplication        : Starting SpringSecurityDemoApplication using Java 16.0.2 on mao with PID 15684 (H:\程序\大三暑假\springSecurity_demo\target\classes started by mao in H:\程序\大三暑假\springSecurity_demo)
2022-08-01 14:58:01.440 DEBUG 15684 --- [           main] m.s.SpringSecurityDemoApplication        : Running with Spring Boot v2.7.2, Spring v5.3.22
2022-08-01 14:58:01.441  INFO 15684 --- [           main] m.s.SpringSecurityDemoApplication        : The following 1 profile is active: "dev"
2022-08-01 14:58:02.318  INFO 15684 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat initialized with port(s): 8080 (http)
2022-08-01 14:58:02.328  INFO 15684 --- [           main] o.apache.catalina.core.StandardService   : Starting service [Tomcat]
2022-08-01 14:58:02.328  INFO 15684 --- [           main] org.apache.catalina.core.StandardEngine  : Starting Servlet engine: [Apache Tomcat/9.0.65]
2022-08-01 14:58:02.417  INFO 15684 --- [           main] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring embedded WebApplicationContext
2022-08-01 14:58:02.418  INFO 15684 --- [           main] w.s.c.ServletWebServerApplicationContext : Root WebApplicationContext: initialization completed in 944 ms
2022-08-01 14:58:02.529  INFO 15684 --- [           main] c.a.d.s.b.a.DruidDataSourceAutoConfigure : Init DruidDataSource
2022-08-01 14:58:02.624  INFO 15684 --- [           main] com.alibaba.druid.pool.DruidDataSource   : {dataSource-1} inited
2022-08-01 14:58:02.730  WARN 15684 --- [           main] c.b.m.core.metadata.TableInfoHelper      : Can not find table primary key in Class: "mao.springsecurity_demo.entity.Administrators".
2022-08-01 14:58:02.735  WARN 15684 --- [           main] c.b.m.core.injector.DefaultSqlInjector   : class mao.springsecurity_demo.entity.Administrators ,Not found @TableId annotation, Cannot use Mybatis-Plus 'xxById' Method.
2022-08-01 14:58:02.793  WARN 15684 --- [           main] c.b.m.core.metadata.TableInfoHelper      : Can not find table primary key in Class: "mao.springsecurity_demo.entity.AdministratorsPassword".
2022-08-01 14:58:02.794  WARN 15684 --- [           main] c.b.m.core.injector.DefaultSqlInjector   : class mao.springsecurity_demo.entity.AdministratorsPassword ,Not found @TableId annotation, Cannot use Mybatis-Plus 'xxById' Method.
 _ _   |_  _ _|_. ___ _ |    _ 
| | |\/|_)(_| | |_\  |_)||_|_\ 
     /               |         
                        3.5.1 
2022-08-01 14:58:03.184  INFO 15684 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Will secure any request with [org.springframework.security.web.session.DisableEncodeUrlFilter@599f1b7, org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@22791b75, org.springframework.security.web.context.SecurityContextPersistenceFilter@119290b9, org.springframework.security.web.header.HeaderWriterFilter@463afa6e, org.springframework.security.web.csrf.CsrfFilter@4c18516, org.springframework.security.web.authentication.logout.LogoutFilter@67b61834, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@3b0d3a63, org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter@615db358, org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter@64f4f12, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@62cbc478, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@7e61e25c, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@37d28938, org.springframework.security.web.session.SessionManagementFilter@7ccd611e, org.springframework.security.web.access.ExceptionTranslationFilter@5d194314, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@45554613]
2022-08-01 14:58:03.241  INFO 15684 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8080 (http) with context path ''
2022-08-01 14:58:03.251  INFO 15684 --- [           main] m.s.SpringSecurityDemoApplication        : Started SpringSecurityDemoApplication in 2.196 seconds (JVM running for 2.818)
```





## 访问



http://localhost:8080/test





![image-20220801145915511](img/SpringSecurity学习笔记/image-20220801145915511.png)



![image-20220801150016039](img/SpringSecurity学习笔记/image-20220801150016039.png)





![image-20220801150025558](img/SpringSecurity学习笔记/image-20220801150025558.png)





## 查看日志



```sh
2022-08-01 14:58:03.241  INFO 15684 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8080 (http) with context path ''
2022-08-01 14:58:03.251  INFO 15684 --- [           main] m.s.SpringSecurityDemoApplication        : Started SpringSecurityDemoApplication in 2.196 seconds (JVM running for 2.818)
2022-08-01 14:59:07.053  INFO 15684 --- [nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring DispatcherServlet 'dispatcherServlet'
2022-08-01 14:59:07.053  INFO 15684 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Initializing Servlet 'dispatcherServlet'
2022-08-01 14:59:07.054  INFO 15684 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Completed initialization in 1 ms
2022-08-01 15:00:21.315 DEBUG 15684 --- [nio-8080-exec-5] m.s.m.A.selectList                       : ==>  Preparing: SELECT administrator_no,administrator_password FROM administrators_password WHERE (administrator_no = ?)
2022-08-01 15:00:21.331 DEBUG 15684 --- [nio-8080-exec-5] m.s.m.A.selectList                       : ==> Parameters: 10001(Long)
2022-08-01 15:00:21.346 DEBUG 15684 --- [nio-8080-exec-5] m.s.m.A.selectList                       : <==      Total: 1
```











# 自定义页面



## login.html



```html
<!DOCTYPE html>

<!--
Project name(项目名称)：springSecurity_demo
  File name(文件名): login
  Authors(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/1
  Time(创建时间)： 15:09
  Description(描述)： 无
-->

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登录</title>
    <link rel="stylesheet" href="css/form.css">
    <link rel="stylesheet" href="css/animate.css">
    <style>
        body {
            background-color: skyblue;
        }
    </style>
</head>
<body>


<div class="text_position">
    <div class="text animated flipInY">
        登录
    </div>
</div>

<div class="form_position">
    <div class="animated bounceInDown">
        <div class="form">
            <form action="/login"  method="post">
                <table border="1">
                    <tr>
                        <td colspan="2" align="center">
                        </td>
                    </tr>
                    <tr>
                        <td class="prompt">用户ID</td>
                        <td>
                            <label>
                                <input class="input" type="text" name="username" required="required">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <td class="prompt">密码</td>
                        <td>
                            <label>
                                <input class="input" type="password" name="password" required="required">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <td colspan="2" align="center">
                            <input class="submit" type="submit" value="提交"/>
                        </td>
                    </tr>
                </table>
            </form>
        </div>
    </div>
</div>
</body>

<script>


</script>

</html>
```





## error.html



```html
<!DOCTYPE html>

<!--
Project name(项目名称)：springSecurity_demo
  File name(文件名): error
  Authors(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/1
  Time(创建时间)： 15:51
  Description(描述)： 无
-->

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>error</title>
    <link rel="stylesheet" href="css/error.css">
</head>
<body>

<a class="warning" href="login.html">错误：账号或者密码不正确</a>

</body>
</html>
```





## index.html



```html
<!DOCTYPE html>

<!--
Project name(项目名称)：springSecurity_demo
  File name(文件名): index
  Authors(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/1
  Time(创建时间)： 18:49
  Description(描述)： 无
-->

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>索引</title>
</head>
<body>
<h1>
  登录成功
</h1>
</body>
</html>
```





## form.css



```css
/*
  Project name(项目名称)：springSecurity_demo 
  File name(文件名): form
  Author(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/1 
  Time(创建时间)： 15:11
  Version(版本): 1.0
  Description(描述)： 无
 */


/*表单位置*/
div.form_position {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
}

/*表单的边框*/
div.form {
    border: 10px skyblue dotted;
}


/*表*/
table {
    width: 600px;
    border-collapse: collapse;
    color: #4edaff;
    background-color: #ffe4da;
    transition: all 1s linear 0s;
}

table:hover {
    background-color: #b4ffab;
    /*width: 800px;*/
    /*transition: all 1s linear 0s;*/
}


/*设置字体*/
td, input, input.input {
    font-size: 30px;
}

input {
    /*font-size: 24px;*/
    /*width: 90%;*/
    color: coral;
}

input.input {
    width: 85%;
    color: coral;
    transition: all 0.5s linear 0s;
}

input.input:hover {
    width: 98%;
    transition: all 0.5s linear 0s;
    background-color: #fcffee;
}


/*设置提示*/
.prompt {
    text-align: center;
    width: 200px;
    transition: all 1s linear 0.2s;
}

.prompt:hover {
    transition: all 1s linear 0.2s;
    color: #ff2e2f;
}

/*提交按钮*/
input.submit {
    color: #6739ff;
}

input.submit:hover {

}

/*最上面的字*/
div.text {
    border: 10px violet dotted;
    text-align: center;
    font-size: 32px;
    color: tomato;
    background: bisque;
}

/*最上面的字的位置*/
div.text_position {
    position: absolute;
    top: 2%;
    left: 50%;
    transform: translate(-50%, 0%);
}
```





## error.css



```css
/*
  Project name(项目名称)：springSecurity_demo 
  File name(文件名): error
  Author(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/1 
  Time(创建时间)： 15:52
  Version(版本): 1.0
  Description(描述)： 无
 */


body {
    margin: 0;
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: rgb(20%, 20%, 20%);
}

a {
    text-decoration: none;
}

.warning {
    color: whitesmoke;
    font-size: 80px;
    font-family: sans-serif;
    font-weight: bold;
    position: relative;
    padding: 0.6em 0.4em;
}

.warning::before,
.warning::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    border: 0.2em solid transparent;
    box-sizing: border-box;
    color: orangered;
    animation: rotating 10s infinite;
}

.warning::before {
    border-top-color: currentColor;
    border-right-color: currentColor;
    z-index: -1;
}

.warning::after {
    border-bottom-color: currentColor;
    border-left-color: currentColor;
    box-shadow: 0.3em 0.3em 0.3em rgba(20%, 20%, 20%, 0.8);
}

@keyframes rotating {
    to {
        transform: rotate(360deg);
    }
}
```





## animate.css



过多，略



![image-20220801191200469](img/SpringSecurity学习笔记/image-20220801191200469.png)









## 更改SecurityConfig类



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html",
                        "/css/**", "/js/**", "/img/**", "/test/noauth")
                .permitAll()
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}

```







## 启动服务



```sh
OpenJDK 64-Bit Server VM warning: Options -Xverify:none and -noverify were deprecated in JDK 13 and will likely be removed in a future release.

  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::                (v2.7.2)

2022-08-01 19:15:20.395  INFO 3744 --- [           main] m.s.SpringSecurityDemoApplication        : Starting SpringSecurityDemoApplication using Java 16.0.2 on mao with PID 3744 (H:\程序\大三暑假\springSecurity_demo\target\classes started by mao in H:\程序\大三暑假\springSecurity_demo)
2022-08-01 19:15:20.398 DEBUG 3744 --- [           main] m.s.SpringSecurityDemoApplication        : Running with Spring Boot v2.7.2, Spring v5.3.22
2022-08-01 19:15:20.398  INFO 3744 --- [           main] m.s.SpringSecurityDemoApplication        : The following 1 profile is active: "dev"
2022-08-01 19:15:21.189  INFO 3744 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat initialized with port(s): 8080 (http)
2022-08-01 19:15:21.196  INFO 3744 --- [           main] o.apache.catalina.core.StandardService   : Starting service [Tomcat]
2022-08-01 19:15:21.196  INFO 3744 --- [           main] org.apache.catalina.core.StandardEngine  : Starting Servlet engine: [Apache Tomcat/9.0.65]
2022-08-01 19:15:21.280  INFO 3744 --- [           main] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring embedded WebApplicationContext
2022-08-01 19:15:21.280  INFO 3744 --- [           main] w.s.c.ServletWebServerApplicationContext : Root WebApplicationContext: initialization completed in 851 ms
2022-08-01 19:15:21.375  INFO 3744 --- [           main] c.a.d.s.b.a.DruidDataSourceAutoConfigure : Init DruidDataSource
2022-08-01 19:15:21.468  INFO 3744 --- [           main] com.alibaba.druid.pool.DruidDataSource   : {dataSource-1} inited
 _ _   |_  _ _|_. ___ _ |    _ 
| | |\/|_)(_| | |_\  |_)||_|_\ 
     /               |         
                        3.5.1 
2022-08-01 19:15:21.807  INFO 3744 --- [           main] o.s.b.a.w.s.WelcomePageHandlerMapping    : Adding welcome page: class path resource [static/index.html]
2022-08-01 19:15:21.975  INFO 3744 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Will secure any request with [org.springframework.security.web.session.DisableEncodeUrlFilter@272778ae, org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@2cccf134, org.springframework.security.web.context.SecurityContextPersistenceFilter@28d739f1, org.springframework.security.web.header.HeaderWriterFilter@212fafd1, org.springframework.security.web.authentication.logout.LogoutFilter@10d18696, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@6b8b5020, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@7e3d2ebd, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@51888019, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@3c18942, org.springframework.security.web.session.SessionManagementFilter@787988f4, org.springframework.security.web.access.ExceptionTranslationFilter@7d59e968, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@4652c74d]
2022-08-01 19:15:22.025  INFO 3744 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8080 (http) with context path ''
2022-08-01 19:15:22.035  INFO 3744 --- [           main] m.s.SpringSecurityDemoApplication        : Started SpringSecurityDemoApplication in 1.958 seconds (JVM running for 2.435)
```





## 访问



http://localhost:8080/test/noauth



![image-20220801191650119](img/SpringSecurity学习笔记/image-20220801191650119.png)



无需登录就能访问



http://localhost:8080



![image-20220801191758820](img/SpringSecurity学习笔记/image-20220801191758820.png)





需要登录



![image-20220801191846791](img/SpringSecurity学习笔记/image-20220801191846791.png)





![image-20220801191900133](img/SpringSecurity学习笔记/image-20220801191900133.png)



登录失败，跳转到错误页面



![image-20220801191947552](img/SpringSecurity学习笔记/image-20220801191947552.png)





![image-20220801191957331](img/SpringSecurity学习笔记/image-20220801191957331.png)





登录成功







# 基于角色或权限进行访问控制



## hasAuthority 方法



在SecurityConfig类的configure方法配置。

如果当前的主体具有指定的权限，则返回 true,否则返回 false



给/test/root资源设置root权限

给/test/admin资源设置admin权限



访问的用户中必须具有相应的权限才能访问





### 更改TestController类



```java
package mao.springsecurity_demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:52
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@RestController
@RequestMapping("/test")
public class TestController
{
    @GetMapping("")
    public String success()
    {
        return "success";
    }

    @GetMapping("/noauth")
    public String noAuth()
    {
        return "noAuth";
    }

    @GetMapping("/root")
    public String root()
    {
        return "root权限，访问成功";
    }

    @GetMapping("/admin")
    public String admin()
    {
        return "admin权限，访问成功";
    }

}
```





### 更改SecurityConfig类



给/test/root资源设置root权限

给/test/admin资源设置admin权限



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html",
                        "/css/**", "/js/**", "/img/**", "/test/noauth")
                .permitAll()
                .antMatchers("/test/root").hasAuthority("root")
                .antMatchers("/test/admin").hasAuthority("admin")
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}
```







### 重启服务





### 访问



http://localhost:8080/test/



![image-20220801194325708](img/SpringSecurity学习笔记/image-20220801194325708.png)



需要登录



用户名和密码：

10001

111111



![image-20220801194410388](img/SpringSecurity学习笔记/image-20220801194410388.png)



无权限要求的能正常访问





访问http://localhost:8080/test/admin



![image-20220801194516817](img/SpringSecurity学习笔记/image-20220801194516817.png)





状态码为403，无权限



访问http://localhost:8080/test/root



![image-20220801194556224](img/SpringSecurity学习笔记/image-20220801194556224.png)





也没有权限





### 更改用户权限



将用户权限更改为admin



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                AuthorityUtils.createAuthorityList("admin"));
    }
}
```





### 重启服务





### 访问



http://localhost:8080/test/



![image-20220801194752940](img/SpringSecurity学习笔记/image-20220801194752940.png)





![image-20220801194803100](img/SpringSecurity学习笔记/image-20220801194803100.png)





无权限要求的能正常访问





访问http://localhost:8080/test/admin



![image-20220801194851810](img/SpringSecurity学习笔记/image-20220801194851810.png)





能访问



访问http://localhost:8080/test/root





![image-20220801194917445](img/SpringSecurity学习笔记/image-20220801194917445.png)



无权限，不能访问









### 更改用户权限



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                AuthorityUtils.createAuthorityList("root"));
    }
}
```





### 重启服务





### 访问



http://localhost:8080/test/



登录过程略



![image-20220801195303038](img/SpringSecurity学习笔记/image-20220801195303038.png)





访问http://localhost:8080/test/admin



![image-20220801195334181](img/SpringSecurity学习笔记/image-20220801195334181.png)



无权限



访问http://localhost:8080/test/root



![image-20220801195401097](img/SpringSecurity学习笔记/image-20220801195401097.png)



能访问







### 更改用户权限



用户同时具有root和admin权限



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("root"));
                AuthorityUtils.createAuthorityList("root","admin"));
    }
}
```





### 重启服务





### 访问



http://localhost:8080/test/



登录过程略





![image-20220801195631089](img/SpringSecurity学习笔记/image-20220801195631089.png)





访问http://localhost:8080/test/admin



![image-20220801195657748](img/SpringSecurity学习笔记/image-20220801195657748.png)



访问成功





访问http://localhost:8080/test/root



![image-20220801195722263](img/SpringSecurity学习笔记/image-20220801195722263.png)





访问成功





## hasAnyAuthority 方法



如果当前的主体有任何提供的角色的话（只要有其中一个权限），返回 true



给/test/rootOrAdmin资源设置root权限和admin权限





### 更改SecurityConfig类



给/test/rootOrAdmin资源设置root权限和admin权限



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html",
                        "/css/**", "/js/**", "/img/**", "/test/noauth")
                .permitAll()
                .antMatchers("/test/root").hasAuthority("root")
                .antMatchers("/test/admin").hasAuthority("admin")
                .antMatchers("/test/rootOrAdmin").hasAnyAuthority("root","admin")
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}
```





## 更改用户权限



权限为root



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                AuthorityUtils.createAuthorityList("root"));
                //AuthorityUtils.createAuthorityList("root","admin"));
    }
}
```





### 重启服务



### 访问



http://localhost:8080/test/rootOrAdmin



![image-20220801201206032](img/SpringSecurity学习笔记/image-20220801201206032.png)



访问成功





### 更改用户权限



权限为admin



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("root","admin"));
    }
}
```





### 重启服务



### 访问



http://localhost:8080/test/rootOrAdmin



![image-20220801201341555](img/SpringSecurity学习笔记/image-20220801201341555.png)





正常访问







### 更改访问权限



更改为admin1，不相关的权限



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                AuthorityUtils.createAuthorityList("admin1"));
                //AuthorityUtils.createAuthorityList("root","admin"));
    }
}
```





### 重启服务





### 访问



http://localhost:8080/test/rootOrAdmin



![image-20220801201519601](img/SpringSecurity学习笔记/image-20220801201519601.png)





无权限访问











## hasRole 方法



如果用户具备给定角色就允许访问



给/test/role_root资源添加角色root



### 更改TestController类



```java
package mao.springsecurity_demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:52
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@RestController
@RequestMapping("/test")
public class TestController
{
    @GetMapping("")
    public String success()
    {
        return "success";
    }

    @GetMapping("/noauth")
    public String noAuth()
    {
        return "noAuth";
    }

    @GetMapping("/root")
    public String root()
    {
        return "root权限，访问成功";
    }

    @GetMapping("/admin")
    public String admin()
    {
        return "admin权限，访问成功";
    }

    @GetMapping("/rootOrAdmin")
    public String rootOrAdmin()
    {
        return "admin或者root权限，访问成功";
    }

    @GetMapping("/role_root")
    public String role_root()
    {
        return "具有role_root角色，访问成功";
    }

}
```







### 更改SecurityConfig类



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html",
                        "/css/**", "/js/**", "/img/**", "/test/noauth")
                .permitAll()
                .antMatchers("/test/root").hasAuthority("root")
                .antMatchers("/test/admin").hasAuthority("admin")
                .antMatchers("/test/rootOrAdmin").hasAnyAuthority("root", "admin")
                .antMatchers("/test/role_root").hasRole("root")
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}
```







### 重启服务







### 访问



http://localhost:8080/test/role_root



![image-20220801212434654](img/SpringSecurity学习笔记/image-20220801212434654.png)



没有权限







### 更改用户权限



授予root角色



在service中，必须添加ROLE_前缀



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("root","admin"));
                AuthorityUtils.createAuthorityList("admin","ROLE_root"));
    }
}
```





### 重启服务



### 访问



http://localhost:8080/test/role_root



![image-20220801212945720](img/SpringSecurity学习笔记/image-20220801212945720.png)



正常访问









## hasAnyRole



表示用户具备任何一个角色都可以访问



给/role_root_or_admin资源设置root和admin角色





### 更改TestController类



```java
package mao.springsecurity_demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:52
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@RestController
@RequestMapping("/test")
public class TestController
{
    @GetMapping("")
    public String success()
    {
        return "success";
    }

    @GetMapping("/noauth")
    public String noAuth()
    {
        return "noAuth";
    }

    @GetMapping("/root")
    public String root()
    {
        return "root权限，访问成功";
    }

    @GetMapping("/admin")
    public String admin()
    {
        return "admin权限，访问成功";
    }

    @GetMapping("/rootOrAdmin")
    public String rootOrAdmin()
    {
        return "admin或者root权限，访问成功";
    }

    @GetMapping("/role_root")
    public String role_root()
    {
        return "具有role_root角色，访问成功";
    }

    @GetMapping("/role_root_or_admin")
    public String role_root_or_admin()
    {
        return "具有root或者admin角色，访问成功";
    }

}
```





### 更改SecurityConfig类



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html",
                        "/css/**", "/js/**", "/img/**", "/test/noauth")
                .permitAll()
                .antMatchers("/test/root").hasAuthority("root")
                .antMatchers("/test/admin").hasAuthority("admin")
                .antMatchers("/test/rootOrAdmin").hasAnyAuthority("root", "admin")
                .antMatchers("/test/role_root").hasRole("root")
                .antMatchers("/test/role_root_or_admin").hasAnyRole("root", "admin")
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}
```





### 重启服务



### 访问



http://localhost:8080/test/role_root_or_admin



![image-20220801213535126](img/SpringSecurity学习笔记/image-20220801213535126.png)





正常访问





### 更改用户权限



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("root","admin"));
                //AuthorityUtils.createAuthorityList("admin", "ROLE_root"));
                AuthorityUtils.createAuthorityList("admin", "ROLE_admin"));
    }
}
```





### 重启服务



### 访问



http://localhost:8080/test/role_root_or_admin



![image-20220801213731693](img/SpringSecurity学习笔记/image-20220801213731693.png)





正常访问





### 更改用户权限



角色为ROLE_admin1



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("root","admin"));
                //AuthorityUtils.createAuthorityList("admin", "ROLE_root"));
                AuthorityUtils.createAuthorityList("admin", "ROLE_admin1"));
    }
}
```





### 重启访问



### 访问



http://localhost:8080/test/role_root_or_admin



![image-20220801213907304](img/SpringSecurity学习笔记/image-20220801213907304.png)







无权限访问





### 更改用户权限



同时具备root和admin权限



```java
package mao.springsecurity_demo.service;

import mao.springsecurity_demo.entity.AdministratorsPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.service
 * Class(类名): AdministratorsLoginService
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/1
 * Time(创建时间)： 14:23
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Service
public class AdministratorsLoginService implements UserDetailsService
{

    private static final Logger log = LoggerFactory.getLogger(AdministratorsLoginService.class);


    @Autowired
    private IAdministratorsPasswordService administratorsPasswordService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        log.debug("进入AdministratorsLoginService");

        //判空
        if (username == null || username.equals(""))
        {
            throw new UsernameNotFoundException("用户名不能为空！");
        }
        Long id = null;
        try
        {
            id = Long.parseLong(username);
        }
        catch (Exception e)
        {
            throw new UsernameNotFoundException("用户名必须为数字！");
        }
        //查数据库
        AdministratorsPassword administratorsPassword = administratorsPasswordService.query().eq("administrator_no", id).one();
        //判断是否存在
        if (administratorsPassword == null || administratorsPassword.getAdministratorNo() == null)
        {
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //将数据放入user对象里并返回
        return new User(administratorsPassword.getAdministratorNo().toString(),
                administratorsPassword.getAdministratorPassword(),
                //AuthorityUtils.createAuthorityList("administrator"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("admin"));
                //AuthorityUtils.createAuthorityList("root","admin"));
                //AuthorityUtils.createAuthorityList("admin", "ROLE_root"));
                //AuthorityUtils.createAuthorityList("admin", "ROLE_admin1"));
                AuthorityUtils.createAuthorityList("admin", "ROLE_admin", "ROLE_root"));
    }
}
```







### 重启服务



### 访问



http://localhost:8080/test/role_root_or_admin



![image-20220801214114066](img/SpringSecurity学习笔记/image-20220801214114066.png)





正常访问











# 自定义 403 页面



## 更改SecurityConfig类

配置异常处理



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录配置
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //异常处理配置，403页面配置
        http.exceptionHandling().accessDeniedPage("/unAuth.html");

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html",
                        "/css/**", "/js/**", "/img/**", "/test/noauth")
                .permitAll()
                .antMatchers("/test/root").hasAuthority("root")
                .antMatchers("/test/admin").hasAuthority("admin")
                .antMatchers("/test/rootOrAdmin").hasAnyAuthority("root", "admin")
                .antMatchers("/test/role_root").hasRole("root")
                .antMatchers("/test/role_root_or_admin").hasAnyRole("root", "admin")
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}
```





## 添加页面



unAuth.html

```html
<!DOCTYPE html>

<!--
Project name(项目名称)：springSecurity_demo
  File name(文件名): unAuth
  Authors(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/1
  Time(创建时间)： 21:59
  Description(描述)： 无
-->

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>无权限访问</title>
    <link rel="stylesheet" href="/css/error.css">
    <link rel="stylesheet" href="/css/animate.css">
</head>
<body>

<div class="animated fadeInDown">
    <div class="warning" href="login.html" onclick="back()">您无权限访问此页面，点击返回</div>
</div>

</body>

<script>

    function back()
    {
        window.history.back()
    }

</script>
</html>
```







## 重启服务





## 访问



![image-20220802130031705](img/SpringSecurity学习笔记/image-20220802130031705.png)





访问http://localhost:8080/test/root页面



![image-20220802130111140](img/SpringSecurity学习笔记/image-20220802130111140.png)













# 用户注销



## 更改索引页面

在索引页面添加一个退出连接



```java
<!DOCTYPE html>

<!--
Project name(项目名称)：springSecurity_demo
  File name(文件名): index
  Authors(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/1
  Time(创建时间)： 18:49
  Description(描述)： 无
-->

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>索引</title>
    <style>
        .logout {
            position: absolute;
            top: 1%;
            right: 0.5%;
            text-decoration: none;
            font-size: 2em;
            transition: all 1s linear 0s;
            color: royalblue;
        }

        .logout:hover {
            transition: all 1s linear 0s;
            color: red;
        }

    </style>
</head>
<body>

<h1>
    登录成功
</h1>

<a class="logout" href="/logout">退出登录</a>

</body>
</html>
```







## 添加退出成功页面



thanks.html

```html
<!DOCTYPE html>

<!--
Project name(项目名称)：springSecurity_demo
  File name(文件名): thanks
  Authors(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/2
  Time(创建时间)： 13:27
  Description(描述)： 无
-->

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>感谢使用</title>
    <link rel="stylesheet" href="/css/thanks.css">
</head>
<body>

<div>
    <div class="thanks">
        <a href="/login.html" class="sign">感谢使用</a>
        <!--<div class="sign">感谢</div>-->
        <div class="strings"></div>
        <div class="pin top"></div>
        <div class="pin left"></div>
        <div class="pin right"></div>
    </div>
</div>

</body>
</html>
```







thanks.css

```css
/*
  Project name(项目名称)：springSecurity_demo 
  File name(文件名): thanks
  Author(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/2 
  Time(创建时间)： 13:27
  Version(版本): 1.0
  Description(描述)： 无
 */


html, body {
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: radial-gradient(circle at center 60%, white, sandybrown);
}

a {
    text-decoration: none;
}

.thanks {
    width: 400px;
    height: 300px;
    position: relative;
    animation: swinging 1.5s ease-in-out infinite alternate;
    transform-origin: 200px 13px;
}

.sign {
    width: 100%;
    height: 200px;
    background: burlywood;
    border-radius: 15px;
    position: absolute;
    bottom: 0;
    font-size: 70px;
    color: saddlebrown;
    font-family: serif;
    font-weight: bold;
    text-align: center;
    line-height: 200px;
    text-shadow: 0 2px 0 rgba(255, 255, 255, 0.3),
    0 -2px 0 rgba(0, 0, 0, 0.7);
}

.strings {
    width: 150px;
    height: 150px;
    border: 5px solid brown;
    position: absolute;
    border-right: none;
    border-bottom: none;
    transform: rotate(45deg);
    top: 38px;
    left: 122px;
}

.pin {
    width: 25px;
    height: 25px;
    border-radius: 50%;
    position: absolute;
}

.pin.top {
    background: gray;
    left: 187px;
}

.pin.left,
.pin.right {
    background: brown;
    top: 110px;
    box-shadow: 0 2px 0 rgba(255, 255, 255, 0.3);
}

.pin.left {
    left: 80px;
}

.pin.right {
    right: 80px;
}

@keyframes swinging {
    from {
        transform: rotate(10deg);
    }

    to {
        transform: rotate(-10deg);
    }
}
```





## 更改SecurityConfig类



在配置类中添加退出映射地址



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录配置
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //异常处理配置，403页面配置
        http.exceptionHandling().accessDeniedPage("/unAuth.html");

        //退出登录配置
        http.logout()
                //设置退出登录的url
                .logoutUrl("/logout")
                //设置退出登录成功后要跳转的url
                .logoutSuccessUrl("/thanks.html")
                .permitAll();

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html", "/thanks.html",
                        "/css/**", "/js/**", "/img/**", "/test/noauth")
                .permitAll()
                .antMatchers("/test/root").hasAuthority("root")
                .antMatchers("/test/admin").hasAuthority("admin")
                .antMatchers("/test/rootOrAdmin").hasAnyAuthority("root", "admin")
                .antMatchers("/test/role_root").hasRole("root")
                .antMatchers("/test/role_root_or_admin").hasAnyRole("root", "admin")
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}
```







## 重启服务



## 访问



http://localhost:8080/



![image-20220802133804417](img/SpringSecurity学习笔记/image-20220802133804417.png)





![image-20220802133826449](img/SpringSecurity学习笔记/image-20220802133826449.png)





点击退出登录



![image-20220802133849347](img/SpringSecurity学习笔记/image-20220802133849347.png)





访问http://localhost:8080/test

http://localhost:8080/test/root

http://localhost:8080/test/admin



![image-20220802133938502](img/SpringSecurity学习笔记/image-20220802133938502.png)



都需要登录









# 注解





## 开启注解功能



在启动类上加上：

```java
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
```



```java
package mao.springsecurity_demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SpringSecurityDemoApplication
{

    public static void main(String[] args)
    {
        SpringApplication.run(SpringSecurityDemoApplication.class, args);
    }

}
```







## @Secured



判断是否具有某个角色，需要注意的是这里匹配的字符串需要添加前缀“ROLE_“



### 添加一个controller



TestAnnotationController



```java
package mao.springsecurity_demo.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestAnnotationController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/2
 * Time(创建时间)： 13:55
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@RestController
@RequestMapping("/test")
public class TestAnnotationController
{
    @Secured({"ROLE_root"})
    @GetMapping("/anno/root")
    public String role_root()
    {
        return "注解测试，当前需要root角色，访问成功";
    }

    @Secured({"ROLE_root1"})
    @GetMapping("/anno/root1")
    public String role_root1()
    {
        return "注解测试，当前需要root1角色，访问成功";
    }

    @Secured({"ROLE_admin"})
    @GetMapping("/anno/admin")
    public String role_admin()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    @Secured({"ROLE_admin1"})
    @GetMapping("/anno/admin1")
    public String role_admin1()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    @Secured({"ROLE_admin", "ROLE_root"})
    @GetMapping("/anno/admin_or_root")
    public String role_admin_or_root()
    {
        return "注解测试，当前需要admin或者root角色，访问成功";
    }

    @Secured({"ROLE_admin", "ROLE_root1"})
    @GetMapping("/anno/admin_or_root1")
    public String role_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1角色，访问成功";
    }

    @Secured({"ROLE_admin1", "ROLE_root1"})
    @GetMapping("/anno/admin1_or_root1")
    public String role_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1角色，访问成功";
    }
}
```





当前用户都具有admin和root角色





### 重启服务





### 访问



访问http://localhost:8080/test/anno/root





![image-20220802140952605](img/SpringSecurity学习笔记/image-20220802140952605.png)





访问http://localhost:8080/test/anno/root1



![image-20220802141016521](img/SpringSecurity学习笔记/image-20220802141016521.png)





访问http://localhost:8080/test/anno/admin



![image-20220802141038418](img/SpringSecurity学习笔记/image-20220802141038418.png)



访问http://localhost:8080/test/anno/admin1





![image-20220802141108175](img/SpringSecurity学习笔记/image-20220802141108175.png)





访问http://localhost:8080/test/anno/admin_or_root



![image-20220802141155225](img/SpringSecurity学习笔记/image-20220802141155225.png)





访问http://localhost:8080/test/anno/admin_or_root1



![image-20220802141226433](img/SpringSecurity学习笔记/image-20220802141226433.png)





访问http://localhost:8080/test/anno/admin1_or_root1





![image-20220802141247920](img/SpringSecurity学习笔记/image-20220802141247920.png)











## @PreAuthorize



用于进入方法前的权限验证





### 更改controller



```java
package mao.springsecurity_demo.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestAnnotationController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/2
 * Time(创建时间)： 13:55
 * Version(版本): 1.0
 * Description(描述)： 无
 */


@RestController
@RequestMapping("/test")
public class TestAnnotationController
{
    /**
     * Role root string.
     *
     * @return the string
     */
    @Secured({"ROLE_root"})
    @GetMapping("/anno/root")
    public String role_root()
    {
        return "注解测试，当前需要root角色，访问成功";
    }

    /**
     * Role root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_root1"})
    @GetMapping("/anno/root1")
    public String role_root1()
    {
        return "注解测试，当前需要root1角色，访问成功";
    }

    /**
     * Role admin string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin"})
    @GetMapping("/anno/admin")
    public String role_admin()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    /**
     * Role admin 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin1"})
    @GetMapping("/anno/admin1")
    public String role_admin1()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    /**
     * Role admin or root string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin", "ROLE_root"})
    @GetMapping("/anno/admin_or_root")
    public String role_admin_or_root()
    {
        return "注解测试，当前需要admin或者root角色，访问成功";
    }

    /**
     * Role admin or root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin", "ROLE_root1"})
    @GetMapping("/anno/admin_or_root1")
    public String role_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1角色，访问成功";
    }

    /**
     * Role admin 1 or root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin1", "ROLE_root1"})
    @GetMapping("/anno/admin1_or_root1")
    public String role_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1角色，访问成功";
    }

    //--------------------------------------------

    /**
     * Authority root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('root')")
    @GetMapping("/anno2/root")
    public String authority_root()
    {
        return "注解测试，当前需要root权限，访问成功";
    }

    /**
     * Authority root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('root1')")
    @GetMapping("/anno2/root1")
    public String authority_root1()
    {
        return "注解测试，当前需要root1权限，访问成功";
    }

    /**
     * Authority admin string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin')")
    @GetMapping("/anno2/admin")
    public String authority_admin()
    {
        return "注解测试，当前需要admin权限，访问成功";
    }

    /**
     * Authority admin 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1')")
    @GetMapping("/anno2/admin1")
    public String authority_admin1()
    {
        return "注解测试，当前需要admin1权限，访问成功";
    }

    /**
     * Authority admin or root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin','root')")
    @GetMapping("/anno2/admin_or_root")
    public String authority_admin_or_root()
    {
        return "注解测试，当前需要admin或者root权限，访问成功";
    }


    /**
     * Authority admin or root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin','root1')")
    @GetMapping("/anno2/admin_or_root1")
    public String authority_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1权限，访问成功";
    }

    /**
     * Authority admin 1 or root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1','root')")
    @GetMapping("/anno2/admin1_or_root")
    public String authority_admin1_or_root()
    {
        return "注解测试，当前需要admin1或者root权限，访问成功";
    }

    /**
     * Authority admin 1 or root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1','root1')")
    @GetMapping("/anno2/admin1_or_root1")
    public String authority_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1权限，访问成功";
    }

}
```





当前用于具有admin一个权限



### 重启服务



### 访问



访问http://localhost:8080/test/anno2/root



![image-20220802214532954](img/SpringSecurity学习笔记/image-20220802214532954.png)





访问http://localhost:8080/test/anno2/roo1



![image-20220802214548978](img/SpringSecurity学习笔记/image-20220802214548978.png)





访问http://localhost:8080/test/anno2/admin



![image-20220802214615250](img/SpringSecurity学习笔记/image-20220802214615250.png)





访问http://localhost:8080/test/anno2/admin1



![image-20220802214632336](img/SpringSecurity学习笔记/image-20220802214632336.png)





访问http://localhost:8080/test/anno2/admin_or_root



![image-20220802214659000](img/SpringSecurity学习笔记/image-20220802214659000.png)





访问http://localhost:8080/test/anno2/admin_or_root1



![image-20220802214714858](img/SpringSecurity学习笔记/image-20220802214714858.png)





访问http://localhost:8080/test/anno2/admin1_or_root



![image-20220802214743061](img/SpringSecurity学习笔记/image-20220802214743061.png)





访问http://localhost:8080/test/anno2/admin1_or_root1



![image-20220802214834150](img/SpringSecurity学习笔记/image-20220802214834150.png)













## @PostAuthorize



用于在方法执行后再进行权限验证，适合验证带有返回值 的权限







### 更改controller



```java
package mao.springsecurity_demo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestAnnotationController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/2
 * Time(创建时间)： 13:55
 * Version(版本): 1.0
 * Description(描述)： 无
 */


@RestController
@RequestMapping("/test")
public class TestAnnotationController
{

    private static final Logger log = LoggerFactory.getLogger(TestAnnotationController.class);

    /**
     * Role root string.
     *
     * @return the string
     */
    @Secured({"ROLE_root"})
    @GetMapping("/anno/root")
    public String role_root()
    {
        return "注解测试，当前需要root角色，访问成功";
    }

    /**
     * Role root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_root1"})
    @GetMapping("/anno/root1")
    public String role_root1()
    {
        return "注解测试，当前需要root1角色，访问成功";
    }

    /**
     * Role admin string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin"})
    @GetMapping("/anno/admin")
    public String role_admin()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    /**
     * Role admin 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin1"})
    @GetMapping("/anno/admin1")
    public String role_admin1()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    /**
     * Role admin or root string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin", "ROLE_root"})
    @GetMapping("/anno/admin_or_root")
    public String role_admin_or_root()
    {
        return "注解测试，当前需要admin或者root角色，访问成功";
    }

    /**
     * Role admin or root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin", "ROLE_root1"})
    @GetMapping("/anno/admin_or_root1")
    public String role_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1角色，访问成功";
    }

    /**
     * Role admin 1 or root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin1", "ROLE_root1"})
    @GetMapping("/anno/admin1_or_root1")
    public String role_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1角色，访问成功";
    }

    //--------------------------------------------

    /**
     * Authority root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('root')")
    @GetMapping("/anno2/root")
    public String authority_root()
    {
        return "注解测试，当前需要root权限，访问成功";
    }

    /**
     * Authority root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('root1')")
    @GetMapping("/anno2/root1")
    public String authority_root1()
    {
        return "注解测试，当前需要root1权限，访问成功";
    }

    /**
     * Authority admin string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin')")
    @GetMapping("/anno2/admin")
    public String authority_admin()
    {
        return "注解测试，当前需要admin权限，访问成功";
    }

    /**
     * Authority admin 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1')")
    @GetMapping("/anno2/admin1")
    public String authority_admin1()
    {
        return "注解测试，当前需要admin1权限，访问成功";
    }

    /**
     * Authority admin or root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin','root')")
    @GetMapping("/anno2/admin_or_root")
    public String authority_admin_or_root()
    {
        return "注解测试，当前需要admin或者root权限，访问成功";
    }


    /**
     * Authority admin or root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin','root1')")
    @GetMapping("/anno2/admin_or_root1")
    public String authority_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1权限，访问成功";
    }

    /**
     * Authority admin 1 or root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1','root')")
    @GetMapping("/anno2/admin1_or_root")
    public String authority_admin1_or_root()
    {
        return "注解测试，当前需要admin1或者root权限，访问成功";
    }

    /**
     * Authority admin 1 or root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1','root1')")
    @GetMapping("/anno2/admin1_or_root1")
    public String authority_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1权限，访问成功";
    }


    //----------------------------------------

    /**
     * Authority 2 root string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('root')")
    @GetMapping("/anno3/root")
    public String authority2_root()
    {
        log.info("PostAuthorize注解测试，当前需要root权限");
        return "PostAuthorize注解测试，当前需要root权限，访问成功";
    }

    /**
     * Authority 2 root 1 string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('root1')")
    @GetMapping("/anno3/root1")
    public String authority2_root1()
    {
        log.info("PostAuthorize注解测试，当前需要root1权限");
        return "PostAuthorize注解测试，当前需要root1权限，访问成功";
    }

    /**
     * Authority 2 admin string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('admin')")
    @GetMapping("/anno3/admin")
    public String authority2_admin()
    {
        log.info("PostAuthorize注解测试，当前需要admin权限");
        return "PostAuthorize注解测试，当前需要admin权限，访问成功";
    }

    /**
     * Authority 2 admin 1 string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('admin1')")
    @GetMapping("/anno3/admin1")
    public String authority2_admin1()
    {
        log.info("PostAuthorize注解测试，当前需要admin1权限");
        return "PostAuthorize注解测试，当前需要admin1权限，访问成功";
    }

}
```







### 重启服务





### 访问



访问http://localhost:8080/test/anno3/root



![image-20220802215817605](img/SpringSecurity学习笔记/image-20220802215817605.png)





访问http://localhost:8080/test/anno3/root1



![image-20220802215836349](img/SpringSecurity学习笔记/image-20220802215836349.png)





访问http://localhost:8080/test/anno3/admin



![image-20220802215853850](img/SpringSecurity学习笔记/image-20220802215853850.png)





访问http://localhost:8080/test/anno3/admin1



![image-20220802215918317](img/SpringSecurity学习笔记/image-20220802215918317.png)







### 查看日志



```sh
2022-08-02 21:57:06.796  INFO 14508 --- [           main] m.s.SpringSecurityDemoApplication        : Starting SpringSecurityDemoApplication using Java 16.0.2 on mao with PID 14508 (H:\程序\大三暑假\springSecurity_demo\target\classes started by mao in H:\程序\大三暑假\springSecurity_demo)
2022-08-02 21:57:06.799 DEBUG 14508 --- [           main] m.s.SpringSecurityDemoApplication        : Running with Spring Boot v2.7.2, Spring v5.3.22
2022-08-02 21:57:06.799  INFO 14508 --- [           main] m.s.SpringSecurityDemoApplication        : The following 1 profile is active: "dev"
2022-08-02 21:57:07.657  INFO 14508 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat initialized with port(s): 8080 (http)
2022-08-02 21:57:07.664  INFO 14508 --- [           main] o.apache.catalina.core.StandardService   : Starting service [Tomcat]
2022-08-02 21:57:07.664  INFO 14508 --- [           main] org.apache.catalina.core.StandardEngine  : Starting Servlet engine: [Apache Tomcat/9.0.65]
2022-08-02 21:57:07.759  INFO 14508 --- [           main] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring embedded WebApplicationContext
2022-08-02 21:57:07.759  INFO 14508 --- [           main] w.s.c.ServletWebServerApplicationContext : Root WebApplicationContext: initialization completed in 925 ms
2022-08-02 21:57:07.906  INFO 14508 --- [           main] c.a.d.s.b.a.DruidDataSourceAutoConfigure : Init DruidDataSource
2022-08-02 21:57:07.994  INFO 14508 --- [           main] com.alibaba.druid.pool.DruidDataSource   : {dataSource-1} inited
 _ _   |_  _ _|_. ___ _ |    _ 
| | |\/|_)(_| | |_\  |_)||_|_\ 
     /               |         
                        3.5.1 
2022-08-02 21:57:08.398  INFO 14508 --- [           main] o.s.b.a.w.s.WelcomePageHandlerMapping    : Adding welcome page: class path resource [static/index.html]
2022-08-02 21:57:08.640  INFO 14508 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Will secure any request with [org.springframework.security.web.session.DisableEncodeUrlFilter@76e4212, org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@23121d14, org.springframework.security.web.context.SecurityContextPersistenceFilter@1c7f9861, org.springframework.security.web.header.HeaderWriterFilter@7d50f2a8, org.springframework.security.web.authentication.logout.LogoutFilter@9b2dc56, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@621f23ac, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@154b8cb6, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@39449465, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@72af90e8, org.springframework.security.web.session.SessionManagementFilter@37ca3ca8, org.springframework.security.web.access.ExceptionTranslationFilter@307cf964, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@79add732]
2022-08-02 21:57:08.698  INFO 14508 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8080 (http) with context path ''
2022-08-02 21:57:08.712  INFO 14508 --- [           main] m.s.SpringSecurityDemoApplication        : Started SpringSecurityDemoApplication in 2.248 seconds (JVM running for 2.73)
2022-08-02 21:57:16.735  INFO 14508 --- [nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring DispatcherServlet 'dispatcherServlet'
2022-08-02 21:57:16.735  INFO 14508 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Initializing Servlet 'dispatcherServlet'
2022-08-02 21:57:16.736  INFO 14508 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Completed initialization in 1 ms
2022-08-02 21:57:20.705 DEBUG 14508 --- [nio-8080-exec-4] m.s.service.AdministratorsLoginService   : 进入AdministratorsLoginService
2022-08-02 21:57:20.952 DEBUG 14508 --- [nio-8080-exec-4] m.s.m.A.selectList                       : ==>  Preparing: SELECT administrator_no,administrator_password FROM administrators_password WHERE (administrator_no = ?)
2022-08-02 21:57:20.969 DEBUG 14508 --- [nio-8080-exec-4] m.s.m.A.selectList                       : ==> Parameters: 10001(Long)
2022-08-02 21:57:20.984 DEBUG 14508 --- [nio-8080-exec-4] m.s.m.A.selectList                       : <==      Total: 1
2022-08-02 21:57:35.557  INFO 14508 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : PostAuthorize注解测试，当前需要root权限
2022-08-02 21:58:30.529  INFO 14508 --- [nio-8080-exec-2] m.s.controller.TestAnnotationController  : PostAuthorize注解测试，当前需要root1权限
2022-08-02 21:58:48.710  INFO 14508 --- [nio-8080-exec-6] m.s.controller.TestAnnotationController  : PostAuthorize注解测试，当前需要admin权限
2022-08-02 21:59:02.441  INFO 14508 --- [nio-8080-exec-7] m.s.controller.TestAnnotationController  : PostAuthorize注解测试，当前需要admin1权限
```









## @PostFilter



权限验证之后对数据进行过滤

Filter target must be a collection, array, map or stream type





### 更改controller



```java
package mao.springsecurity_demo.controller;

import mao.springsecurity_demo.entity.Administrators;
import mao.springsecurity_demo.service.IAdministratorsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;


/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestAnnotationController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/2
 * Time(创建时间)： 13:55
 * Version(版本): 1.0
 * Description(描述)： 无
 */


@RestController
@RequestMapping("/test")
public class TestAnnotationController
{

    private static final Logger log = LoggerFactory.getLogger(TestAnnotationController.class);

    /**
     * Role root string.
     *
     * @return the string
     */
    @Secured({"ROLE_root"})
    @GetMapping("/anno/root")
    public String role_root()
    {
        return "注解测试，当前需要root角色，访问成功";
    }

    /**
     * Role root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_root1"})
    @GetMapping("/anno/root1")
    public String role_root1()
    {
        return "注解测试，当前需要root1角色，访问成功";
    }

    /**
     * Role admin string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin"})
    @GetMapping("/anno/admin")
    public String role_admin()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    /**
     * Role admin 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin1"})
    @GetMapping("/anno/admin1")
    public String role_admin1()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    /**
     * Role admin or root string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin", "ROLE_root"})
    @GetMapping("/anno/admin_or_root")
    public String role_admin_or_root()
    {
        return "注解测试，当前需要admin或者root角色，访问成功";
    }

    /**
     * Role admin or root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin", "ROLE_root1"})
    @GetMapping("/anno/admin_or_root1")
    public String role_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1角色，访问成功";
    }

    /**
     * Role admin 1 or root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin1", "ROLE_root1"})
    @GetMapping("/anno/admin1_or_root1")
    public String role_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1角色，访问成功";
    }

    //--------------------------------------------

    /**
     * Authority root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('root')")
    @GetMapping("/anno2/root")
    public String authority_root()
    {
        return "注解测试，当前需要root权限，访问成功";
    }

    /**
     * Authority root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('root1')")
    @GetMapping("/anno2/root1")
    public String authority_root1()
    {
        return "注解测试，当前需要root1权限，访问成功";
    }

    /**
     * Authority admin string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin')")
    @GetMapping("/anno2/admin")
    public String authority_admin()
    {
        return "注解测试，当前需要admin权限，访问成功";
    }

    /**
     * Authority admin 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1')")
    @GetMapping("/anno2/admin1")
    public String authority_admin1()
    {
        return "注解测试，当前需要admin1权限，访问成功";
    }

    /**
     * Authority admin or root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin','root')")
    @GetMapping("/anno2/admin_or_root")
    public String authority_admin_or_root()
    {
        return "注解测试，当前需要admin或者root权限，访问成功";
    }


    /**
     * Authority admin or root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin','root1')")
    @GetMapping("/anno2/admin_or_root1")
    public String authority_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1权限，访问成功";
    }

    /**
     * Authority admin 1 or root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1','root')")
    @GetMapping("/anno2/admin1_or_root")
    public String authority_admin1_or_root()
    {
        return "注解测试，当前需要admin1或者root权限，访问成功";
    }

    /**
     * Authority admin 1 or root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1','root1')")
    @GetMapping("/anno2/admin1_or_root1")
    public String authority_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1权限，访问成功";
    }


    //----------------------------------------

    /**
     * Authority 2 root string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('root')")
    @GetMapping("/anno3/root")
    public String authority2_root()
    {
        log.info("PostAuthorize注解测试，当前需要root权限");
        return "PostAuthorize注解测试，当前需要root权限，访问成功";
    }

    /**
     * Authority 2 root 1 string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('root1')")
    @GetMapping("/anno3/root1")
    public String authority2_root1()
    {
        log.info("PostAuthorize注解测试，当前需要root1权限");
        return "PostAuthorize注解测试，当前需要root1权限，访问成功";
    }

    /**
     * Authority 2 admin string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('admin')")
    @GetMapping("/anno3/admin")
    public String authority2_admin()
    {
        log.info("PostAuthorize注解测试，当前需要admin权限");
        return "PostAuthorize注解测试，当前需要admin权限，访问成功";
    }

    /**
     * Authority 2 admin 1 string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('admin1')")
    @GetMapping("/anno3/admin1")
    public String authority2_admin1()
    {
        log.info("PostAuthorize注解测试，当前需要admin1权限");
        return "PostAuthorize注解测试，当前需要admin1权限，访问成功";
    }

    //-------------------------------------

    /**
     * Anno 4 1 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorNo==10002L")
    @GetMapping("/anno4/1")
    public List<Administrators> anno4_1()
    {
        log.info("执行/anno4/1");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators = new Administrators();
        administrators.setAdministratorNo(10002L);
        list.add(administrators);
        return list;
    }

    /**
     * Anno 4 2 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorNo==10003L")
    @GetMapping("/anno4/2")
    public List<Administrators> anno4_2()
    {
        log.info("执行/anno4/2");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators = new Administrators();
        administrators.setAdministratorNo(10002L);
        list.add(administrators);
        return list;
    }

    /**
     * Anno 4 3 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorNo==10003L")
    @GetMapping("/anno4/3")
    public List<Administrators> anno4_3()
    {
        log.info("执行/anno4/3");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators1 = new Administrators();
        administrators1.setAdministratorNo(10002L);
        Administrators administrators2 = new Administrators();
        administrators2.setAdministratorNo(10003L);
        Administrators administrators3 = new Administrators();
        administrators3.setAdministratorNo(10004L);
        list.add(administrators1);
        list.add(administrators2);
        list.add(administrators3);
        return list;
    }

    /**
     * Anno 4 4 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorNo!=10003L")
    @GetMapping("/anno4/4")
    public List<Administrators> anno4_4()
    {
        log.info("执行/anno4/4");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators1 = new Administrators();
        administrators1.setAdministratorNo(10002L);
        Administrators administrators2 = new Administrators();
        administrators2.setAdministratorNo(10003L);
        Administrators administrators3 = new Administrators();
        administrators3.setAdministratorNo(10004L);
        list.add(administrators1);
        list.add(administrators2);
        list.add(administrators3);
        return list;
    }

    /**
     * Anno 4 5 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorName!=null")
    @GetMapping("/anno4/5")
    public List<Administrators> anno4_5()
    {
        log.info("执行/anno4/5");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators1 = new Administrators();
        administrators1.setAdministratorNo(10002L);
        administrators1.setAdministratorName("张三");
        Administrators administrators2 = new Administrators();
        administrators2.setAdministratorNo(10003L);
        Administrators administrators3 = new Administrators();
        administrators3.setAdministratorNo(10004L);
        list.add(administrators1);
        list.add(administrators2);
        list.add(administrators3);
        return list;
    }

    /**
     * Anno 4 6 list.
     *
     * @return the list
     */
    @PostFilter("(filterObject.administratorName!=null)&&(filterObject.administratorSex.equals('男'))")
    @GetMapping("/anno4/6")
    public List<Administrators> anno4_6()
    {
        log.info("执行/anno4/6");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators1 = new Administrators();
        administrators1.setAdministratorNo(10002L);
        administrators1.setAdministratorName("张三");
        administrators1.setAdministratorSex("女");
        Administrators administrators2 = new Administrators();
        administrators2.setAdministratorNo(10003L);
        Administrators administrators3 = new Administrators();
        administrators3.setAdministratorNo(10004L);
        Administrators administrators4 = new Administrators();
        administrators4.setAdministratorNo(10005L);
        administrators4.setAdministratorName("李四");
        administrators4.setAdministratorSex("男");
        list.add(administrators1);
        list.add(administrators2);
        list.add(administrators3);
        list.add(administrators4);
        return list;
    }

    @Autowired
    private IAdministratorsService administratorsService;

    /**
     * 需求：从数据库查询性别为女的数据
     *
     * @return List<Administrators> 对象
     */
    @PostFilter("filterObject.administratorSex.equals('女')")
    @GetMapping("/anno4/7")
    public List<Administrators> anno4_7()
    {
        log.info("执行/anno4/7");
        List<Administrators> list = administratorsService.query().list();
        return list;
    }

    /**
     * 需求：从数据库查询性别为女的数据
     *
     * @return List<Administrators> 对象
     */
    @PostFilter("filterObject.administratorSex.equals('男')")
    @GetMapping("/anno4/8")
    public List<Administrators> anno4_8()
    {
        log.info("执行/anno4/8");
        List<Administrators> list = administratorsService.query().list();
        return list;
    }

}
```





### 重启服务



### 访问



访问http://localhost:8080/test/anno4/1



![image-20220802231119781](img/SpringSecurity学习笔记/image-20220802231119781.png)





访问http://localhost:8080/test/anno4/2



![image-20220802231137632](img/SpringSecurity学习笔记/image-20220802231137632.png)





访问http://localhost:8080/test/anno4/3



![image-20220802231151403](img/SpringSecurity学习笔记/image-20220802231151403.png)





访问http://localhost:8080/test/anno4/4



![image-20220802231210488](img/SpringSecurity学习笔记/image-20220802231210488.png)





访问http://localhost:8080/test/anno4/5



![image-20220802231233571](img/SpringSecurity学习笔记/image-20220802231233571.png)



访问http://localhost:8080/test/anno4/6



![image-20220802231252453](img/SpringSecurity学习笔记/image-20220802231252453.png)





访问http://localhost:8080/test/anno4/7



![image-20220802231312180](img/SpringSecurity学习笔记/image-20220802231312180.png)





```json
[{"administratorNo":10001,"administratorName":"唐淑玲","administratorSex":"女","administratorTelephoneNumber":"13801143638","administratorJob":"校长","administratorIdcard":"439165200008274998"},{"administratorNo":10002,"administratorName":"隗瑶","administratorSex":"女","administratorTelephoneNumber":"15302990518","administratorJob":"副校长","administratorIdcard":"422080200209084877"},{"administratorNo":10003,"administratorName":"甫黛","administratorSex":"女","administratorTelephoneNumber":"13204546288","administratorJob":"副校长","administratorIdcard":"435943200304212416"},{"administratorNo":10004,"administratorName":"祖瑶影","administratorSex":"女","administratorTelephoneNumber":"13606453515","administratorJob":"计算机学院院长","administratorIdcard":"437336199902254962"},{"administratorNo":10008,"administratorName":"牛巧","administratorSex":"女","administratorTelephoneNumber":"15906467901","administratorJob":"管理员","administratorIdcard":"427804200109122721"},{"administratorNo":10011,"administratorName":"酆馥霞","administratorSex":"女","administratorTelephoneNumber":"13805661106","administratorJob":"管理员","administratorIdcard":"432958199903241775"},{"administratorNo":10014,"administratorName":"贡瑾育","administratorSex":"女","administratorTelephoneNumber":"13800310215","administratorJob":"管理员","administratorIdcard":"436145200003095722"},{"administratorNo":10015,"administratorName":"钟园璐","administratorSex":"女","administratorTelephoneNumber":"15204391113","administratorJob":"管理员","administratorIdcard":"431764199909143390"},{"administratorNo":10018,"administratorName":"常荣芝","administratorSex":"女","administratorTelephoneNumber":"13704638779","administratorJob":"管理员","administratorIdcard":"422857200104226262"},{"administratorNo":10021,"administratorName":"富凝珠","administratorSex":"女","administratorTelephoneNumber":"13002418313","administratorJob":"管理员","administratorIdcard":"427292200111188298"},{"administratorNo":10028,"administratorName":"百咏眉","administratorSex":"女","administratorTelephoneNumber":"15900848912","administratorJob":"管理员","administratorIdcard":"432945200311205420"},{"administratorNo":10029,"administratorName":"益育","administratorSex":"女","administratorTelephoneNumber":"13003655837","administratorJob":"管理员","administratorIdcard":"431957200302288367"},{"administratorNo":10030,"administratorName":"姓岚玲","administratorSex":"女","administratorTelephoneNumber":"15500945048","administratorJob":"管理员","administratorIdcard":"427975200306115062"}]
```





访问http://localhost:8080/test/anno4/8



![image-20220802231351915](img/SpringSecurity学习笔记/image-20220802231351915.png)







```json
[{"administratorNo":10005,"administratorName":"裴策奇","administratorSex":"男","administratorTelephoneNumber":"13906801424","administratorJob":"计算机学院副院长","administratorIdcard":"436700200205167159"},{"administratorNo":10006,"administratorName":"常新","administratorSex":"男","administratorTelephoneNumber":"15200884859","administratorJob":"计算机学院副院长","administratorIdcard":"425230199905174567"},{"administratorNo":10007,"administratorName":"文波","administratorSex":"男","administratorTelephoneNumber":"13002966149","administratorJob":"计算机学院副院长","administratorIdcard":"440405199901072724"},{"administratorNo":10009,"administratorName":"琴有奇","administratorSex":"男","administratorTelephoneNumber":"13207633407","administratorJob":"管理员","administratorIdcard":"437776200107198012"},{"administratorNo":10010,"administratorName":"容彪诚","administratorSex":"男","administratorTelephoneNumber":"13704933439","administratorJob":"管理员","administratorIdcard":"435874200305254814"},{"administratorNo":10012,"administratorName":"仇生良","administratorSex":"男","administratorTelephoneNumber":"13204292788","administratorJob":"管理员","administratorIdcard":"422574200108068146"},{"administratorNo":10013,"administratorName":"蒙海冠","administratorSex":"男","administratorTelephoneNumber":"13003853784","administratorJob":"管理员","administratorIdcard":"423806200205164383"},{"administratorNo":10016,"administratorName":"向冠","administratorSex":"男","administratorTelephoneNumber":"15005897305","administratorJob":"管理员","administratorIdcard":"430461200304265635"},{"administratorNo":10017,"administratorName":"彭辉生","administratorSex":"男","administratorTelephoneNumber":"13700370300","administratorJob":"管理员","administratorIdcard":"432611200105216186"},{"administratorNo":10019,"administratorName":"李明","administratorSex":"男","administratorTelephoneNumber":"13804178399","administratorJob":"管理员","administratorIdcard":"434880200009014080"},{"administratorNo":10020,"administratorName":"白鸣坚","administratorSex":"男","administratorTelephoneNumber":"15601790970","administratorJob":"管理员","administratorIdcard":"428468199903043027"},{"administratorNo":10022,"administratorName":"宰广震","administratorSex":"男","administratorTelephoneNumber":"13306854395","administratorJob":"管理员","administratorIdcard":"435022200307255751"},{"administratorNo":10023,"administratorName":"曾奇利","administratorSex":"男","administratorTelephoneNumber":"13503052929","administratorJob":"管理员","administratorIdcard":"431917200309113634"},{"administratorNo":10024,"administratorName":"离良光","administratorSex":"男","administratorTelephoneNumber":"13205957069","administratorJob":"管理员","administratorIdcard":"427136200309201542"},{"administratorNo":10025,"administratorName":"都德光","administratorSex":"男","administratorTelephoneNumber":"13908498869","administratorJob":"管理员","administratorIdcard":"427667200102066356"},{"administratorNo":10026,"administratorName":"终泰","administratorSex":"男","administratorTelephoneNumber":"13402995699","administratorJob":"管理员","administratorIdcard":"421738200201021058"},{"administratorNo":10027,"administratorName":"乐振","administratorSex":"男","administratorTelephoneNumber":"13802950621","administratorJob":"管理员","administratorIdcard":"432185200103143063"}]
```







### 查看日志



```sh
2022-08-02 23:10:59.357  INFO 18460 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8080 (http) with context path ''
2022-08-02 23:10:59.371  INFO 18460 --- [           main] m.s.SpringSecurityDemoApplication        : Started SpringSecurityDemoApplication in 2.248 seconds (JVM running for 2.746)
2022-08-02 23:10:59.543  INFO 18460 --- [nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring DispatcherServlet 'dispatcherServlet'
2022-08-02 23:10:59.543  INFO 18460 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Initializing Servlet 'dispatcherServlet'
2022-08-02 23:10:59.544  INFO 18460 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Completed initialization in 0 ms
2022-08-02 23:11:06.937 DEBUG 18460 --- [nio-8080-exec-5] m.s.service.AdministratorsLoginService   : 进入AdministratorsLoginService
2022-08-02 23:11:07.183 DEBUG 18460 --- [nio-8080-exec-5] m.s.m.A.selectList                       : ==>  Preparing: SELECT administrator_no,administrator_password FROM administrators_password WHERE (administrator_no = ?)
2022-08-02 23:11:07.200 DEBUG 18460 --- [nio-8080-exec-5] m.s.m.A.selectList                       : ==> Parameters: 10001(Long)
2022-08-02 23:11:07.216 DEBUG 18460 --- [nio-8080-exec-5] m.s.m.A.selectList                       : <==      Total: 1
2022-08-02 23:11:07.240  INFO 18460 --- [nio-8080-exec-6] m.s.controller.TestAnnotationController  : 执行/anno4/1
2022-08-02 23:11:33.067  INFO 18460 --- [nio-8080-exec-7] m.s.controller.TestAnnotationController  : 执行/anno4/2
2022-08-02 23:11:46.867  INFO 18460 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 执行/anno4/3
2022-08-02 23:12:03.320  INFO 18460 --- [nio-8080-exec-1] m.s.controller.TestAnnotationController  : 执行/anno4/4
2022-08-02 23:12:28.642  INFO 18460 --- [nio-8080-exec-2] m.s.controller.TestAnnotationController  : 执行/anno4/5
2022-08-02 23:12:44.683  INFO 18460 --- [nio-8080-exec-3] m.s.controller.TestAnnotationController  : 执行/anno4/6
2022-08-02 23:13:05.323  INFO 18460 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 执行/anno4/7
2022-08-02 23:13:05.335  WARN 18460 --- [nio-8080-exec-5] c.a.druid.pool.DruidAbstractDataSource   : discard long time none received connection. , jdbcUrl : jdbc:mysql://localhost:3306/student1, version : 1.2.8, lastPacketReceivedIdleMillis : 118122
2022-08-02 23:13:05.356 DEBUG 18460 --- [nio-8080-exec-5] m.s.m.AdministratorsMapper.selectList    : ==>  Preparing: SELECT administrator_no,administrator_name,administrator_sex,administrator_telephone_number,administrator_job,administrator_idcard FROM administrators
2022-08-02 23:13:05.357 DEBUG 18460 --- [nio-8080-exec-5] m.s.m.AdministratorsMapper.selectList    : ==> Parameters: 
2022-08-02 23:13:05.363 DEBUG 18460 --- [nio-8080-exec-5] m.s.m.AdministratorsMapper.selectList    : <==      Total: 30
2022-08-02 23:13:46.580  INFO 18460 --- [nio-8080-exec-6] m.s.controller.TestAnnotationController  : 执行/anno4/8
2022-08-02 23:13:46.580 DEBUG 18460 --- [nio-8080-exec-6] m.s.m.AdministratorsMapper.selectList    : ==>  Preparing: SELECT administrator_no,administrator_name,administrator_sex,administrator_telephone_number,administrator_job,administrator_idcard FROM administrators
2022-08-02 23:13:46.581 DEBUG 18460 --- [nio-8080-exec-6] m.s.m.AdministratorsMapper.selectList    : ==> Parameters: 
2022-08-02 23:13:46.585 DEBUG 18460 --- [nio-8080-exec-6] m.s.m.AdministratorsMapper.selectList    : <==      Total: 30
```







##  @PreFilter



用于进入控制器之前对数据进行过滤



### 更改controller

```java
package mao.springsecurity_demo.controller;

import mao.springsecurity_demo.entity.Administrators;
import mao.springsecurity_demo.service.IAdministratorsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;


/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.controller
 * Class(类名): TestAnnotationController
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/2
 * Time(创建时间)： 13:55
 * Version(版本): 1.0
 * Description(描述)： 无
 */


@RestController
@RequestMapping("/test")
public class TestAnnotationController
{

    private static final Logger log = LoggerFactory.getLogger(TestAnnotationController.class);

    /**
     * Role root string.
     *
     * @return the string
     */
    @Secured({"ROLE_root"})
    @GetMapping("/anno/root")
    public String role_root()
    {
        return "注解测试，当前需要root角色，访问成功";
    }

    /**
     * Role root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_root1"})
    @GetMapping("/anno/root1")
    public String role_root1()
    {
        return "注解测试，当前需要root1角色，访问成功";
    }

    /**
     * Role admin string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin"})
    @GetMapping("/anno/admin")
    public String role_admin()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    /**
     * Role admin 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin1"})
    @GetMapping("/anno/admin1")
    public String role_admin1()
    {
        return "注解测试，当前需要admin角色，访问成功";
    }

    /**
     * Role admin or root string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin", "ROLE_root"})
    @GetMapping("/anno/admin_or_root")
    public String role_admin_or_root()
    {
        return "注解测试，当前需要admin或者root角色，访问成功";
    }

    /**
     * Role admin or root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin", "ROLE_root1"})
    @GetMapping("/anno/admin_or_root1")
    public String role_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1角色，访问成功";
    }

    /**
     * Role admin 1 or root 1 string.
     *
     * @return the string
     */
    @Secured({"ROLE_admin1", "ROLE_root1"})
    @GetMapping("/anno/admin1_or_root1")
    public String role_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1角色，访问成功";
    }

    //--------------------------------------------

    /**
     * Authority root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('root')")
    @GetMapping("/anno2/root")
    public String authority_root()
    {
        return "注解测试，当前需要root权限，访问成功";
    }

    /**
     * Authority root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('root1')")
    @GetMapping("/anno2/root1")
    public String authority_root1()
    {
        return "注解测试，当前需要root1权限，访问成功";
    }

    /**
     * Authority admin string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin')")
    @GetMapping("/anno2/admin")
    public String authority_admin()
    {
        return "注解测试，当前需要admin权限，访问成功";
    }

    /**
     * Authority admin 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1')")
    @GetMapping("/anno2/admin1")
    public String authority_admin1()
    {
        return "注解测试，当前需要admin1权限，访问成功";
    }

    /**
     * Authority admin or root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin','root')")
    @GetMapping("/anno2/admin_or_root")
    public String authority_admin_or_root()
    {
        return "注解测试，当前需要admin或者root权限，访问成功";
    }


    /**
     * Authority admin or root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin','root1')")
    @GetMapping("/anno2/admin_or_root1")
    public String authority_admin_or_root1()
    {
        return "注解测试，当前需要admin或者root1权限，访问成功";
    }

    /**
     * Authority admin 1 or root string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1','root')")
    @GetMapping("/anno2/admin1_or_root")
    public String authority_admin1_or_root()
    {
        return "注解测试，当前需要admin1或者root权限，访问成功";
    }

    /**
     * Authority admin 1 or root 1 string.
     *
     * @return the string
     */
    @PreAuthorize("hasAnyAuthority('admin1','root1')")
    @GetMapping("/anno2/admin1_or_root1")
    public String authority_admin1_or_root1()
    {
        return "注解测试，当前需要admin1或者root1权限，访问成功";
    }


    //----------------------------------------

    /**
     * Authority 2 root string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('root')")
    @GetMapping("/anno3/root")
    public String authority2_root()
    {
        log.info("PostAuthorize注解测试，当前需要root权限");
        return "PostAuthorize注解测试，当前需要root权限，访问成功";
    }

    /**
     * Authority 2 root 1 string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('root1')")
    @GetMapping("/anno3/root1")
    public String authority2_root1()
    {
        log.info("PostAuthorize注解测试，当前需要root1权限");
        return "PostAuthorize注解测试，当前需要root1权限，访问成功";
    }

    /**
     * Authority 2 admin string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('admin')")
    @GetMapping("/anno3/admin")
    public String authority2_admin()
    {
        log.info("PostAuthorize注解测试，当前需要admin权限");
        return "PostAuthorize注解测试，当前需要admin权限，访问成功";
    }

    /**
     * Authority 2 admin 1 string.
     *
     * @return the string
     */
    @PostAuthorize("hasAnyAuthority('admin1')")
    @GetMapping("/anno3/admin1")
    public String authority2_admin1()
    {
        log.info("PostAuthorize注解测试，当前需要admin1权限");
        return "PostAuthorize注解测试，当前需要admin1权限，访问成功";
    }

    //-------------------------------------

    /**
     * Anno 4 1 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorNo==10002L")
    @GetMapping("/anno4/1")
    public List<Administrators> anno4_1()
    {
        log.info("执行/anno4/1");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators = new Administrators();
        administrators.setAdministratorNo(10002L);
        list.add(administrators);
        return list;
    }

    /**
     * Anno 4 2 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorNo==10003L")
    @GetMapping("/anno4/2")
    public List<Administrators> anno4_2()
    {
        log.info("执行/anno4/2");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators = new Administrators();
        administrators.setAdministratorNo(10002L);
        list.add(administrators);
        return list;
    }

    /**
     * Anno 4 3 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorNo==10003L")
    @GetMapping("/anno4/3")
    public List<Administrators> anno4_3()
    {
        log.info("执行/anno4/3");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators1 = new Administrators();
        administrators1.setAdministratorNo(10002L);
        Administrators administrators2 = new Administrators();
        administrators2.setAdministratorNo(10003L);
        Administrators administrators3 = new Administrators();
        administrators3.setAdministratorNo(10004L);
        list.add(administrators1);
        list.add(administrators2);
        list.add(administrators3);
        return list;
    }

    /**
     * Anno 4 4 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorNo!=10003L")
    @GetMapping("/anno4/4")
    public List<Administrators> anno4_4()
    {
        log.info("执行/anno4/4");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators1 = new Administrators();
        administrators1.setAdministratorNo(10002L);
        Administrators administrators2 = new Administrators();
        administrators2.setAdministratorNo(10003L);
        Administrators administrators3 = new Administrators();
        administrators3.setAdministratorNo(10004L);
        list.add(administrators1);
        list.add(administrators2);
        list.add(administrators3);
        return list;
    }

    /**
     * Anno 4 5 list.
     *
     * @return the list
     */
    @PostFilter("filterObject.administratorName!=null")
    @GetMapping("/anno4/5")
    public List<Administrators> anno4_5()
    {
        log.info("执行/anno4/5");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators1 = new Administrators();
        administrators1.setAdministratorNo(10002L);
        administrators1.setAdministratorName("张三");
        Administrators administrators2 = new Administrators();
        administrators2.setAdministratorNo(10003L);
        Administrators administrators3 = new Administrators();
        administrators3.setAdministratorNo(10004L);
        list.add(administrators1);
        list.add(administrators2);
        list.add(administrators3);
        return list;
    }

    /**
     * Anno 4 6 list.
     *
     * @return the list
     */
    @PostFilter("(filterObject.administratorName!=null)&&(filterObject.administratorSex.equals('男'))")
    @GetMapping("/anno4/6")
    public List<Administrators> anno4_6()
    {
        log.info("执行/anno4/6");
        List<Administrators> list = new ArrayList<>();
        Administrators administrators1 = new Administrators();
        administrators1.setAdministratorNo(10002L);
        administrators1.setAdministratorName("张三");
        administrators1.setAdministratorSex("女");
        Administrators administrators2 = new Administrators();
        administrators2.setAdministratorNo(10003L);
        Administrators administrators3 = new Administrators();
        administrators3.setAdministratorNo(10004L);
        Administrators administrators4 = new Administrators();
        administrators4.setAdministratorNo(10005L);
        administrators4.setAdministratorName("李四");
        administrators4.setAdministratorSex("男");
        list.add(administrators1);
        list.add(administrators2);
        list.add(administrators3);
        list.add(administrators4);
        return list;
    }

    @Autowired
    private IAdministratorsService administratorsService;

    /**
     * 需求：从数据库查询性别为女的数据
     *
     * @return List<Administrators> 对象
     */
    @PostFilter("filterObject.administratorSex.equals('女')")
    @GetMapping("/anno4/7")
    public List<Administrators> anno4_7()
    {
        log.info("执行/anno4/7");
        List<Administrators> list = administratorsService.query().list();
        return list;
    }

    /**
     * 需求：从数据库查询性别为女的数据
     *
     * @return List<Administrators> 对象
     */
    @PostFilter("filterObject.administratorSex.equals('男')")
    @GetMapping("/anno4/8")
    public List<Administrators> anno4_8()
    {
        log.info("执行/anno4/8");
        List<Administrators> list = administratorsService.query().list();
        return list;
    }

    
    //---------------------------------------------
    
    /**
     * 查询全部
     *
     * @return List<Administrators>
     */
    @GetMapping("/anno5/0")
    public List<Administrators> anno5_0()
    {
        log.info("执行/anno5/0");
        List<Administrators> list = administratorsService.query().list();
        return list;
    }

    /**
     * 只需要性别为男的数据
     *
     * @param list List<Administrators>
     * @return List<Administrators> 结果
     */
    @PreFilter("filterObject.administratorSex.equals('男')")
    @PostMapping("/anno5/1")
    public List<Administrators> anno5_1(@RequestBody List<Administrators> list)
    {
        log.info("执行/anno5/1");
        for (Administrators administrators : list)
        {
            log.debug("\n" + administrators + "\n");
        }
        return list;
    }

    /**
     * 只需要性别为女的数据
     *
     * @param list List<Administrators>
     * @return List<Administrators> 结果
     */
    @PreFilter("filterObject.administratorSex.equals('女')")
    @PostMapping("/anno5/2")
    public List<Administrators> anno5_2(@RequestBody List<Administrators> list)
    {
        log.info("执行/anno5/2");
        for (Administrators administrators : list)
        {
            log.debug("\n" + administrators + "\n");
        }
        return list;
    }

    /**
     * 只需要名字包含‘唐’字的数据
     *
     * @param list List<Administrators>
     * @return List<Administrators> 结果
     */
    @PreFilter("filterObject.administratorName.contains('唐')")
    @PostMapping("/anno5/3")
    public List<Administrators> anno5_3(@RequestBody List<Administrators> list)
    {
        log.info("执行/anno5/3");
        for (Administrators administrators : list)
        {
            log.debug("\n" + administrators + "\n");
        }
        return list;
    }

}

```





### 更改SecurityConfig



```java
package mao.springsecurity_demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录配置
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //异常处理配置，403页面配置
        http.exceptionHandling().accessDeniedPage("/unAuth.html");

        //退出登录配置
        http.logout()
                //设置退出登录的url
                .logoutUrl("/logout")
                //设置退出登录成功后要跳转的url
                .logoutSuccessUrl("/thanks.html")
                .permitAll();

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html", "/thanks.html",
                        "/css/**", "/js/**", "/img/**",
                        "/test/noauth", "/test/anno5/**")
                .permitAll()
                .antMatchers("/test/root").hasAuthority("root")
                .antMatchers("/test/admin").hasAuthority("admin")
                .antMatchers("/test/rootOrAdmin").hasAnyAuthority("root", "admin")
                .antMatchers("/test/role_root").hasRole("root")
                .antMatchers("/test/role_root_or_admin").hasAnyRole("root", "admin")
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}
```





### 重启服务



### 访问

使用postman测试



请求体数据：

```json
[
    {
        "administratorNo": 10001,
        "administratorName": "唐淑玲",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13801143638",
        "administratorJob": "校长",
        "administratorIdcard": "439165200008274998"
    },
    {
        "administratorNo": 10002,
        "administratorName": "隗瑶",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15302990518",
        "administratorJob": "副校长",
        "administratorIdcard": "422080200209084877"
    },
    {
        "administratorNo": 10003,
        "administratorName": "甫黛",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13204546288",
        "administratorJob": "副校长",
        "administratorIdcard": "435943200304212416"
    },
    {
        "administratorNo": 10004,
        "administratorName": "祖瑶影",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13606453515",
        "administratorJob": "计算机学院院长",
        "administratorIdcard": "437336199902254962"
    },
    {
        "administratorNo": 10005,
        "administratorName": "裴策奇",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13906801424",
        "administratorJob": "计算机学院副院长",
        "administratorIdcard": "436700200205167159"
    },
    {
        "administratorNo": 10006,
        "administratorName": "常新",
        "administratorSex": "男",
        "administratorTelephoneNumber": "15200884859",
        "administratorJob": "计算机学院副院长",
        "administratorIdcard": "425230199905174567"
    },
    {
        "administratorNo": 10007,
        "administratorName": "文波",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13002966149",
        "administratorJob": "计算机学院副院长",
        "administratorIdcard": "440405199901072724"
    },
    {
        "administratorNo": 10008,
        "administratorName": "牛巧",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15906467901",
        "administratorJob": "管理员",
        "administratorIdcard": "427804200109122721"
    },
    {
        "administratorNo": 10009,
        "administratorName": "琴有奇",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13207633407",
        "administratorJob": "管理员",
        "administratorIdcard": "437776200107198012"
    },
    {
        "administratorNo": 10010,
        "administratorName": "容彪诚",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13704933439",
        "administratorJob": "管理员",
        "administratorIdcard": "435874200305254814"
    },
    {
        "administratorNo": 10011,
        "administratorName": "酆馥霞",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13805661106",
        "administratorJob": "管理员",
        "administratorIdcard": "432958199903241775"
    },
    {
        "administratorNo": 10012,
        "administratorName": "仇生良",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13204292788",
        "administratorJob": "管理员",
        "administratorIdcard": "422574200108068146"
    },
    {
        "administratorNo": 10013,
        "administratorName": "蒙海冠",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13003853784",
        "administratorJob": "管理员",
        "administratorIdcard": "423806200205164383"
    },
    {
        "administratorNo": 10014,
        "administratorName": "贡瑾育",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13800310215",
        "administratorJob": "管理员",
        "administratorIdcard": "436145200003095722"
    },
    {
        "administratorNo": 10015,
        "administratorName": "钟园璐",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15204391113",
        "administratorJob": "管理员",
        "administratorIdcard": "431764199909143390"
    },
    {
        "administratorNo": 10016,
        "administratorName": "向冠",
        "administratorSex": "男",
        "administratorTelephoneNumber": "15005897305",
        "administratorJob": "管理员",
        "administratorIdcard": "430461200304265635"
    },
    {
        "administratorNo": 10017,
        "administratorName": "彭辉生",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13700370300",
        "administratorJob": "管理员",
        "administratorIdcard": "432611200105216186"
    },
    {
        "administratorNo": 10018,
        "administratorName": "常荣芝",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13704638779",
        "administratorJob": "管理员",
        "administratorIdcard": "422857200104226262"
    },
    {
        "administratorNo": 10019,
        "administratorName": "李明",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13804178399",
        "administratorJob": "管理员",
        "administratorIdcard": "434880200009014080"
    },
    {
        "administratorNo": 10020,
        "administratorName": "白鸣坚",
        "administratorSex": "男",
        "administratorTelephoneNumber": "15601790970",
        "administratorJob": "管理员",
        "administratorIdcard": "428468199903043027"
    },
    {
        "administratorNo": 10021,
        "administratorName": "富凝珠",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13002418313",
        "administratorJob": "管理员",
        "administratorIdcard": "427292200111188298"
    },
    {
        "administratorNo": 10022,
        "administratorName": "宰广震",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13306854395",
        "administratorJob": "管理员",
        "administratorIdcard": "435022200307255751"
    },
    {
        "administratorNo": 10023,
        "administratorName": "曾奇利",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13503052929",
        "administratorJob": "管理员",
        "administratorIdcard": "431917200309113634"
    },
    {
        "administratorNo": 10024,
        "administratorName": "离良光",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13205957069",
        "administratorJob": "管理员",
        "administratorIdcard": "427136200309201542"
    },
    {
        "administratorNo": 10025,
        "administratorName": "都德光",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13908498869",
        "administratorJob": "管理员",
        "administratorIdcard": "427667200102066356"
    },
    {
        "administratorNo": 10026,
        "administratorName": "终泰",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13402995699",
        "administratorJob": "管理员",
        "administratorIdcard": "421738200201021058"
    },
    {
        "administratorNo": 10027,
        "administratorName": "乐振",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13802950621",
        "administratorJob": "管理员",
        "administratorIdcard": "432185200103143063"
    },
    {
        "administratorNo": 10028,
        "administratorName": "百咏眉",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15900848912",
        "administratorJob": "管理员",
        "administratorIdcard": "432945200311205420"
    },
    {
        "administratorNo": 10029,
        "administratorName": "益育",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13003655837",
        "administratorJob": "管理员",
        "administratorIdcard": "431957200302288367"
    },
    {
        "administratorNo": 10030,
        "administratorName": "姓岚玲",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15500945048",
        "administratorJob": "管理员",
        "administratorIdcard": "427975200306115062"
    }
]
```





访问http://localhost:8080/test/anno5/1

post请求



![image-20220803132115503](img/SpringSecurity学习笔记/image-20220803132115503.png)









查看结果



![image-20220803132157012](img/SpringSecurity学习笔记/image-20220803132157012.png)





```json
[
    {
        "administratorNo": 10005,
        "administratorName": "裴策奇",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13906801424",
        "administratorJob": "计算机学院副院长",
        "administratorIdcard": "436700200205167159"
    },
    {
        "administratorNo": 10006,
        "administratorName": "常新",
        "administratorSex": "男",
        "administratorTelephoneNumber": "15200884859",
        "administratorJob": "计算机学院副院长",
        "administratorIdcard": "425230199905174567"
    },
    {
        "administratorNo": 10007,
        "administratorName": "文波",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13002966149",
        "administratorJob": "计算机学院副院长",
        "administratorIdcard": "440405199901072724"
    },
    {
        "administratorNo": 10009,
        "administratorName": "琴有奇",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13207633407",
        "administratorJob": "管理员",
        "administratorIdcard": "437776200107198012"
    },
    {
        "administratorNo": 10010,
        "administratorName": "容彪诚",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13704933439",
        "administratorJob": "管理员",
        "administratorIdcard": "435874200305254814"
    },
    {
        "administratorNo": 10012,
        "administratorName": "仇生良",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13204292788",
        "administratorJob": "管理员",
        "administratorIdcard": "422574200108068146"
    },
    {
        "administratorNo": 10013,
        "administratorName": "蒙海冠",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13003853784",
        "administratorJob": "管理员",
        "administratorIdcard": "423806200205164383"
    },
    {
        "administratorNo": 10016,
        "administratorName": "向冠",
        "administratorSex": "男",
        "administratorTelephoneNumber": "15005897305",
        "administratorJob": "管理员",
        "administratorIdcard": "430461200304265635"
    },
    {
        "administratorNo": 10017,
        "administratorName": "彭辉生",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13700370300",
        "administratorJob": "管理员",
        "administratorIdcard": "432611200105216186"
    },
    {
        "administratorNo": 10019,
        "administratorName": "李明",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13804178399",
        "administratorJob": "管理员",
        "administratorIdcard": "434880200009014080"
    },
    {
        "administratorNo": 10020,
        "administratorName": "白鸣坚",
        "administratorSex": "男",
        "administratorTelephoneNumber": "15601790970",
        "administratorJob": "管理员",
        "administratorIdcard": "428468199903043027"
    },
    {
        "administratorNo": 10022,
        "administratorName": "宰广震",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13306854395",
        "administratorJob": "管理员",
        "administratorIdcard": "435022200307255751"
    },
    {
        "administratorNo": 10023,
        "administratorName": "曾奇利",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13503052929",
        "administratorJob": "管理员",
        "administratorIdcard": "431917200309113634"
    },
    {
        "administratorNo": 10024,
        "administratorName": "离良光",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13205957069",
        "administratorJob": "管理员",
        "administratorIdcard": "427136200309201542"
    },
    {
        "administratorNo": 10025,
        "administratorName": "都德光",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13908498869",
        "administratorJob": "管理员",
        "administratorIdcard": "427667200102066356"
    },
    {
        "administratorNo": 10026,
        "administratorName": "终泰",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13402995699",
        "administratorJob": "管理员",
        "administratorIdcard": "421738200201021058"
    },
    {
        "administratorNo": 10027,
        "administratorName": "乐振",
        "administratorSex": "男",
        "administratorTelephoneNumber": "13802950621",
        "administratorJob": "管理员",
        "administratorIdcard": "432185200103143063"
    }
]
```





查看日志



```sh
2022-08-03 13:21:28.760  INFO 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 执行/anno5/1
2022-08-03 13:21:28.760 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10005
administratorName：裴策奇
administratorSex：男
administratorTelephoneNumber：13906801424
administratorJob：计算机学院副院长
administratorIdcard：436700200205167159


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10006
administratorName：常新
administratorSex：男
administratorTelephoneNumber：15200884859
administratorJob：计算机学院副院长
administratorIdcard：425230199905174567


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10007
administratorName：文波
administratorSex：男
administratorTelephoneNumber：13002966149
administratorJob：计算机学院副院长
administratorIdcard：440405199901072724


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10009
administratorName：琴有奇
administratorSex：男
administratorTelephoneNumber：13207633407
administratorJob：管理员
administratorIdcard：437776200107198012


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10010
administratorName：容彪诚
administratorSex：男
administratorTelephoneNumber：13704933439
administratorJob：管理员
administratorIdcard：435874200305254814


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10012
administratorName：仇生良
administratorSex：男
administratorTelephoneNumber：13204292788
administratorJob：管理员
administratorIdcard：422574200108068146


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10013
administratorName：蒙海冠
administratorSex：男
administratorTelephoneNumber：13003853784
administratorJob：管理员
administratorIdcard：423806200205164383


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10016
administratorName：向冠
administratorSex：男
administratorTelephoneNumber：15005897305
administratorJob：管理员
administratorIdcard：430461200304265635


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10017
administratorName：彭辉生
administratorSex：男
administratorTelephoneNumber：13700370300
administratorJob：管理员
administratorIdcard：432611200105216186


2022-08-03 13:21:28.761 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10019
administratorName：李明
administratorSex：男
administratorTelephoneNumber：13804178399
administratorJob：管理员
administratorIdcard：434880200009014080


2022-08-03 13:21:28.762 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10020
administratorName：白鸣坚
administratorSex：男
administratorTelephoneNumber：15601790970
administratorJob：管理员
administratorIdcard：428468199903043027


2022-08-03 13:21:28.762 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10022
administratorName：宰广震
administratorSex：男
administratorTelephoneNumber：13306854395
administratorJob：管理员
administratorIdcard：435022200307255751


2022-08-03 13:21:28.762 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10023
administratorName：曾奇利
administratorSex：男
administratorTelephoneNumber：13503052929
administratorJob：管理员
administratorIdcard：431917200309113634


2022-08-03 13:21:28.762 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10024
administratorName：离良光
administratorSex：男
administratorTelephoneNumber：13205957069
administratorJob：管理员
administratorIdcard：427136200309201542


2022-08-03 13:21:28.762 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10025
administratorName：都德光
administratorSex：男
administratorTelephoneNumber：13908498869
administratorJob：管理员
administratorIdcard：427667200102066356


2022-08-03 13:21:28.762 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10026
administratorName：终泰
administratorSex：男
administratorTelephoneNumber：13402995699
administratorJob：管理员
administratorIdcard：421738200201021058


2022-08-03 13:21:28.762 DEBUG 6988 --- [nio-8080-exec-5] m.s.controller.TestAnnotationController  : 
administratorNo：10027
administratorName：乐振
administratorSex：男
administratorTelephoneNumber：13802950621
administratorJob：管理员
administratorIdcard：432185200103143063
```





访问http://localhost:8080/test/anno5/2

post请求



![image-20220803132712576](img/SpringSecurity学习笔记/image-20220803132712576.png)





查看结果



![image-20220803132748443](img/SpringSecurity学习笔记/image-20220803132748443.png)







```json
[
    {
        "administratorNo": 10001,
        "administratorName": "唐淑玲",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13801143638",
        "administratorJob": "校长",
        "administratorIdcard": "439165200008274998"
    },
    {
        "administratorNo": 10002,
        "administratorName": "隗瑶",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15302990518",
        "administratorJob": "副校长",
        "administratorIdcard": "422080200209084877"
    },
    {
        "administratorNo": 10003,
        "administratorName": "甫黛",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13204546288",
        "administratorJob": "副校长",
        "administratorIdcard": "435943200304212416"
    },
    {
        "administratorNo": 10004,
        "administratorName": "祖瑶影",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13606453515",
        "administratorJob": "计算机学院院长",
        "administratorIdcard": "437336199902254962"
    },
    {
        "administratorNo": 10008,
        "administratorName": "牛巧",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15906467901",
        "administratorJob": "管理员",
        "administratorIdcard": "427804200109122721"
    },
    {
        "administratorNo": 10011,
        "administratorName": "酆馥霞",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13805661106",
        "administratorJob": "管理员",
        "administratorIdcard": "432958199903241775"
    },
    {
        "administratorNo": 10014,
        "administratorName": "贡瑾育",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13800310215",
        "administratorJob": "管理员",
        "administratorIdcard": "436145200003095722"
    },
    {
        "administratorNo": 10015,
        "administratorName": "钟园璐",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15204391113",
        "administratorJob": "管理员",
        "administratorIdcard": "431764199909143390"
    },
    {
        "administratorNo": 10018,
        "administratorName": "常荣芝",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13704638779",
        "administratorJob": "管理员",
        "administratorIdcard": "422857200104226262"
    },
    {
        "administratorNo": 10021,
        "administratorName": "富凝珠",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13002418313",
        "administratorJob": "管理员",
        "administratorIdcard": "427292200111188298"
    },
    {
        "administratorNo": 10028,
        "administratorName": "百咏眉",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15900848912",
        "administratorJob": "管理员",
        "administratorIdcard": "432945200311205420"
    },
    {
        "administratorNo": 10029,
        "administratorName": "益育",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13003655837",
        "administratorJob": "管理员",
        "administratorIdcard": "431957200302288367"
    },
    {
        "administratorNo": 10030,
        "administratorName": "姓岚玲",
        "administratorSex": "女",
        "administratorTelephoneNumber": "15500945048",
        "administratorJob": "管理员",
        "administratorIdcard": "427975200306115062"
    }
]
```



查看日志

```sh
2022-08-03 13:27:34.328  INFO 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 执行/anno5/2
2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10001
administratorName：唐淑玲
administratorSex：女
administratorTelephoneNumber：13801143638
administratorJob：校长
administratorIdcard：439165200008274998


2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10002
administratorName：隗瑶
administratorSex：女
administratorTelephoneNumber：15302990518
administratorJob：副校长
administratorIdcard：422080200209084877


2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10003
administratorName：甫黛
administratorSex：女
administratorTelephoneNumber：13204546288
administratorJob：副校长
administratorIdcard：435943200304212416


2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10004
administratorName：祖瑶影
administratorSex：女
administratorTelephoneNumber：13606453515
administratorJob：计算机学院院长
administratorIdcard：437336199902254962


2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10008
administratorName：牛巧
administratorSex：女
administratorTelephoneNumber：15906467901
administratorJob：管理员
administratorIdcard：427804200109122721


2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10011
administratorName：酆馥霞
administratorSex：女
administratorTelephoneNumber：13805661106
administratorJob：管理员
administratorIdcard：432958199903241775


2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10014
administratorName：贡瑾育
administratorSex：女
administratorTelephoneNumber：13800310215
administratorJob：管理员
administratorIdcard：436145200003095722


2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10015
administratorName：钟园璐
administratorSex：女
administratorTelephoneNumber：15204391113
administratorJob：管理员
administratorIdcard：431764199909143390


2022-08-03 13:27:34.329 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10018
administratorName：常荣芝
administratorSex：女
administratorTelephoneNumber：13704638779
administratorJob：管理员
administratorIdcard：422857200104226262


2022-08-03 13:27:34.330 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10021
administratorName：富凝珠
administratorSex：女
administratorTelephoneNumber：13002418313
administratorJob：管理员
administratorIdcard：427292200111188298


2022-08-03 13:27:34.330 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10028
administratorName：百咏眉
administratorSex：女
administratorTelephoneNumber：15900848912
administratorJob：管理员
administratorIdcard：432945200311205420


2022-08-03 13:27:34.330 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10029
administratorName：益育
administratorSex：女
administratorTelephoneNumber：13003655837
administratorJob：管理员
administratorIdcard：431957200302288367


2022-08-03 13:27:34.330 DEBUG 6988 --- [nio-8080-exec-8] m.s.controller.TestAnnotationController  : 
administratorNo：10030
administratorName：姓岚玲
administratorSex：女
administratorTelephoneNumber：15500945048
administratorJob：管理员
administratorIdcard：427975200306115062
```





访问http://localhost:8080/test/anno5/3

post请求





![image-20220803132910025](img/SpringSecurity学习笔记/image-20220803132910025.png)





查看结果



![image-20220803132941806](img/SpringSecurity学习笔记/image-20220803132941806.png)



```json
[
    {
        "administratorNo": 10001,
        "administratorName": "唐淑玲",
        "administratorSex": "女",
        "administratorTelephoneNumber": "13801143638",
        "administratorJob": "校长",
        "administratorIdcard": "439165200008274998"
    }
]
```



查看日志



```sh
2022-08-03 13:29:22.806  INFO 6988 --- [nio-8080-exec-2] m.s.controller.TestAnnotationController  : 执行/anno5/3
2022-08-03 13:29:22.806 DEBUG 6988 --- [nio-8080-exec-2] m.s.controller.TestAnnotationController  : 
administratorNo：10001
administratorName：唐淑玲
administratorSex：女
administratorTelephoneNumber：13801143638
administratorJob：校长
administratorIdcard：439165200008274998
```









# 基于数据库实现自动登录



即关闭浏览器再重新打开还能访问访问





## 创建表



```sql
CREATE TABLE `persistent_logins` (
 `username` varchar(64) NOT NULL,
 `series` varchar(64) NOT NULL,
 `token` varchar(64) NOT NULL,
 `last_used` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE 
CURRENT_TIMESTAMP,
 PRIMARY KEY (`series`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```



```sh
C:\Users\mao>mysql -u root -p
Enter password: ********
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.0.27 MySQL Community Server - GPL

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| cloud_order        |
| cloud_user         |
| hotel              |
| information_schema |
| mysql              |
| nacos              |
| performance_schema |
| sakila             |
| seata              |
| seata_demo         |
| shop               |
| student            |
| student1           |
| student_test       |
| sys                |
| test               |
| tx                 |
| world              |
+--------------------+
18 rows in set (0.01 sec)

mysql> use student1;
Database changed
mysql> show tables;
+-------------------------+
| Tables_in_student1      |
+-------------------------+
| administrators          |
| administrators_password |
| class                   |
| course                  |
| forum                   |
| login_log               |
| news                    |
| score                   |
| student                 |
| student_password        |
| teach                   |
| teacher                 |
| teacher_password        |
+-------------------------+
13 rows in set (0.01 sec)

mysql>
mysql> CREATE TABLE `persistent_logins` (
    ->  `username` varchar(64) NOT NULL,
    ->  `series` varchar(64) NOT NULL,
    ->  `token` varchar(64) NOT NULL,
    ->  `last_used` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE
    -> CURRENT_TIMESTAMP,
    ->  PRIMARY KEY (`series`)
    -> ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
Query OK, 0 rows affected, 1 warning (0.02 sec)

mysql> show tables;
+-------------------------+
| Tables_in_student1      |
+-------------------------+
| administrators          |
| administrators_password |
| class                   |
| course                  |
| forum                   |
| login_log               |
| news                    |
| persistent_logins       |
| score                   |
| student                 |
| student_password        |
| teach                   |
| teacher                 |
| teacher_password        |
+-------------------------+
14 rows in set (0.00 sec)

mysql>
```





## 编写配置类



创建一个配置类AutoLoginSecurityConfig

```java
package mao.springsecurity_demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): AutoLoginSecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/8/3
 * Time(创建时间)： 13:43
 * Version(版本): 1.0
 * Description(描述)： 自动登录的配置
 */

@Configuration
public class AutoLoginSecurityConfig
{
    @Autowired
    private DataSource dataSource;

    @Bean
    public PersistentTokenRepository persistentTokenRepository()
    {
        //创建对应的实现类的对象
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        //设置数据源
        jdbcTokenRepository.setDataSource(dataSource);
        //自动创建表
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }
}
```





## 更改SecurityConfig



```java
package mao.springsecurity_demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

/**
 * Project name(项目名称)：springSecurity_demo
 * Package(包名): mao.springsecurity_demo.config
 * Class(类名): SecurityConfig
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/7/30
 * Time(创建时间)： 20:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Autowired
    private PersistentTokenRepository persistentTokenRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //表单登录配置
        http.formLogin()
                //设置登录页面
                .loginPage("/login.html")
                //设置哪个是登录的 url
                .loginProcessingUrl("/login")
                //设置登录成功之后跳转到哪个 url
                .defaultSuccessUrl("/index.html", false)
                //.successForwardUrl("/index")
                //设置登录失败之后跳转到哪个url
                .failureUrl("/error.html")
                //.failureForwardUrl("fail")
                //设置表单的用户名项参数名称
                .usernameParameter("username")
                //设置表单的密码项参数名称
                .passwordParameter("password");

        //关闭csrf
        http.csrf().disable();

        //异常处理配置，403页面配置
        http.exceptionHandling().accessDeniedPage("/unAuth.html");

        //退出登录配置
        http.logout()
                //设置退出登录的url
                .logoutUrl("/logout")
                //设置退出登录成功后要跳转的url
                .logoutSuccessUrl("/thanks.html")
                .permitAll();

        //自动登录配置
        http.rememberMe()
                //指定要使用的PersistentTokenRepository 。默认是使用TokenBasedRememberMeServices
                .tokenRepository(persistentTokenRepository)
                //指定当记住我令牌有效时用于查找UserDetails的UserDetailsService
                .userDetailsService(userDetailsService)
                //设置有效期，单位是秒，默认是2周时间。即使项目重新启动下次也可以正常登录
                .tokenValiditySeconds(2 * 60)
                //设置表单的记住密码项参数名称，默认是remember-me
                .rememberMeParameter("remember-me");

        //认证配置
        http.authorizeRequests()
                //指定页面不需要验证
                .antMatchers("/login.html", "/login", "/error.html", "/thanks.html",
                        "/css/**", "/js/**", "/img/**",
                        "/test/noauth", "/test/anno5/**")
                .permitAll()
                .antMatchers("/test/root").hasAuthority("root")
                .antMatchers("/test/admin").hasAuthority("admin")
                .antMatchers("/test/rootOrAdmin").hasAnyAuthority("root", "admin")
                .antMatchers("/test/role_root").hasRole("root")
                .antMatchers("/test/role_root_or_admin").hasAnyRole("root", "admin")
                //其它请求都需要身份认证
                .anyRequest()
                .authenticated();

    }


/*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
*/

}

```







## 更改表单



添加一个input标签

```html
<input type="checkbox"name="remember-me"title="记住密码"/>
```





```html
<!DOCTYPE html>

<!--
Project name(项目名称)：springSecurity_demo
  File name(文件名): login
  Authors(作者）: mao
  Author QQ：1296193245
  GitHub：https://github.com/maomao124/
  Date(创建日期)： 2022/8/1
  Time(创建时间)： 15:09
  Description(描述)： 无
-->

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登录</title>
    <link rel="stylesheet" href="css/form.css">
    <link rel="stylesheet" href="css/animate.css">
    <style>
        body {
            background-color: skyblue;
        }

        #remember-me {
            width: 300px;
            height: 40px;
        }
    </style>
</head>
<body>


<div class="text_position">
    <div class="text animated flipInY">
        登录
    </div>
</div>

<div class="form_position">
    <div class="animated bounceInDown">
        <div class="form">
            <form action="/login" method="post">
                <table border="1">
                    <tr>
                        <td colspan="2" align="center">
                        </td>
                    </tr>
                    <tr>
                        <td class="prompt">用户ID</td>
                        <td>
                            <label>
                                <input class="input" type="text" name="username" required="required">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <td class="prompt">密码</td>
                        <td>
                            <label>
                                <input class="input" type="password" name="password" required="required">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <td class="prompt">记住密码</td>
                        <td>
                            <label>
                                <input id="remember-me" class="input" type="checkbox" name="remember-me" title="记住密码">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <td colspan="2" align="center">
                            <input class="submit" type="submit" value="提交"/>
                        </td>
                    </tr>
                </table>
            </form>
        </div>
    </div>
</div>
</body>

<script>


</script>

</html>
```







## 重启服务



## 访问



登录

勾选记住密码



![image-20220803141723361](img/SpringSecurity学习笔记/image-20220803141723361.png)



![image-20220803141754998](img/SpringSecurity学习笔记/image-20220803141754998.png)







## 访问数据库



![image-20220803141833237](img/SpringSecurity学习笔记/image-20220803141833237.png)







## 重启浏览器



直接跳过了登录



![image-20220803141913216](img/SpringSecurity学习笔记/image-20220803141913216.png)







## 访问数据库



最后一个字段的数据被改变

![image-20220803142022415](img/SpringSecurity学习笔记/image-20220803142022415.png)





## 等待token过期

token过期后重启浏览器再访问



![image-20220803142302506](img/SpringSecurity学习笔记/image-20220803142302506.png)



需要登录





## 再次登录



![image-20220803142402996](img/SpringSecurity学习笔记/image-20220803142402996.png)





## 查看数据库



![image-20220803142423066](img/SpringSecurity学习笔记/image-20220803142423066.png)







## 退出登录



点击退出登录



![image-20220803142519735](img/SpringSecurity学习笔记/image-20220803142519735.png)





## 查看数据库



![image-20220803142535687](img/SpringSecurity学习笔记/image-20220803142535687.png)





如果再次重启浏览器再访问，就会需要登录













# CSRF

