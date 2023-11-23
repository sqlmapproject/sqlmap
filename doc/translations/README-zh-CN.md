# mySqlmap - 基于sqlmap包含Web任务管理界面的SQL注入扫描器

mySqlmap是sqlmap的一个分支和修改版本，它是一个备受欢迎的SQL注入扫描器。本分支旨在通过添加基于Web的任务管理功能来增强sqlmap的功能，让您可以更轻松地管理和执行SQL注入扫描任务。mySqlmap提供了直观且功能强大的Web界面，使您能够轻松控制扫描任务的各个方面，为您的安全测试工作提供便利和效率。

## 特点

- **Web界面的任务管理**：通过用户友好的Web界面，您可以直观地管理和监控SQL注入扫描任务。启动、暂停、终止和删除任务只需轻点几下，操作简单明了。
- **详细的任务日志**：每个扫描任务都有详细的日志记录，方便您进行故障排除和分析。您可以深入了解扫描的进展和结果，快速定位问题并采取相应措施。
- **注入点智能标记**：mySqlmap能够清晰标记被扫描应用程序中的注入点，使您能够快速定位潜在的安全风险。不再花费大量时间来手动分析和确认注入点的位置。
- **载荷详情一目了然**：查看每个注入点的载荷详情，帮助您更好地理解和分析注入漏洞。mySqlmap提供方便的界面，让您清楚了解每个注入点的攻击载荷，更高效地开展后续工作。

除了强大的Web界面，我们还为您提供了基于Java的Burp Suite客户端插件，进一步简化了扫描任务的提交流程。该插件与Burp Suite完美集成，让您能够直接从Burp Suite应用程序内部提交扫描任务，提高工作效率。

## 安装

开始使用mySqlmap，请按照以下步骤进行操作：

### 1. 从GitHub上克隆mySqlmay存储库：

   ```shell
   git clone https://github.com/GitHubNull/mysqlmap.git
   ```

### 2. 确保已安装Python [3.7+]。

### 3. 运行和配置
#### 3.1. 打开命令提示符或终端并导航到项目的根目录。
#### 3.2. 执行以下命令启动mySqlmap api服务：
```shell
   python sqlmapapi.py -s
``` 
![command line shotcut](../../images/mySqlmap-command-line.png)

#### 3.3. 启动服务器运行之后，打开一个Web浏览器（推荐使用Google Chrome）并输入以下URL：[mySqlmap web ui： http://127.0.0.1:8775](http://127.0.0.1:8775)  
#### 3.4. web页面任务管理界面将在浏览器中显示。您可以方便地管理和监视您的sqlmap扫描任务。
![mySqlmap web ui](../../images/mySqlmap-web-ui.png)
> 请注意，为了访问基于Web的管理界面，SQLMap API服务器需要运行。 
> 在使用界面时，请确保服务器始终保持运行。

### 4. Burp Suite客户端插件
#### 4.1. 从GitHub存储库下载插件：[mySqlmapClient: https://github.com/GitHubNull/mySqlmapClient](https://github.com/GitHubNull/mySqlmapClient)
#### 4.2. 在Burp Suite中安装插件：
![mySqlmapClient configuration ui](../../images/mySqlmapClient-setting-ui.png)

#### 4.3. 配置插件

##### 4.3.1. 打开插件配置页面：
![mySqlmapClient configuration ui](../../images/mySqlmapClient-setting-ui.png) 

##### 4.3.2. 输入SQLMap API服务器地址（或保持默认值）

##### 4.3.3. 输入SQLMap API服务器端口（或保持默认值）

#### 4.3.4. 输入SQLMap API临时请求文件目录（或保持默认值）

#### 4.3.5. 单击连接按钮以连接mySqlmap api 服务

#### 4.3.6. 单击保存按钮保存配置

![mySqlClient settng ui after connected to mySqlmap api](../../images/mySqlmapClient-setting-ui-after-connected.png) 

#### 4.4. 使用插件
![mySqlmap web ui](../../images/mySqlmapClient-shotcut.png)  


子项目
----
* [mySqlmapClient](https://github.com/GitHubNull/mySqlmapClient)
* [mySqlmapWebTaskManager](https://github.com/GitHubNull/mySqlmapWebTaskManager)

## 贡献

我们欢迎社区成员为mySqlmap贡献代码，改进项目的功能和易用性。如果您想贡献代码，请遵循以下准则：

1. Fork存储库并为您的功能或错误修复创建一个新的分支。

2. 确保您的代码符合现有的编码风格和约定。

3. 充分测试您的更改，确保其质量和稳定性。

4. 提交一个拉取请求，清晰地描述您的贡献目的和引入的更改。

我们热切期待您的贡献，共同推动mySqlmap的发展和改进！

## 许可证

mySqlmap基于[许可证]许可发布。请查阅[LICENSE](/LICENSE)文件以了解更多详情。

## 免责声明

mySqlmap是一个旨在进行合法安全测试的工具。在扫描任何系统或应用程序之前，请确保获得适当的授权。mySqlmap的作者不对使用该工具进行任何滥用或非法活动承担责任。

## 联系方式

如果您有任何问题、建议或反馈，请通过[github]与我们联系。

感谢您选择mySqlmap！我们希望它能够成为您进行SQL注入测试的得力助手，为您的安全工作注入更多便利和效率。期待与您一起改进和完善mySqlmap！