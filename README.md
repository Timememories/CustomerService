## 项目说明文档 (Project Documentation)

## 1. 项目基本信息 (Basic Project Information)

|项目信息 (Project Info)|详情 (Details)|
|---|---|
|项目名称 (Project Name)|SmartSupport 智能客服管理系统|
|项目版本 (Project Version)|v1.0.0|
|开发语言 (Development Language)|前端 (Frontend)：JavaScript/HTML/CSS；后端 (Backend)：Python|
|开发日期 (Development Date)|2025|
|适用场景 (Application Scenarios)|企业级客户服务管理、在线咨询、预约调度|
## 2. 项目概述 (Project Overview)

### 中文

SmartSupport 智能客服管理系统是一套全流程的客户服务解决方案，旨在打通用户咨询、服务预约、工单处理全链路，为企业构建高效、标准化的客服体系。系统基于角色权限设计，为普通用户、客服人员、系统管理员提供差异化功能模块，兼顾用户体验与管理效率，支持多终端适配，满足企业线上客服场景的全维度需求。

### English

SmartSupport Intelligent Customer Service Management System is a full-process customer service solution designed to connect the entire link of user consultation, service appointment, and work order processing, helping enterprises build an efficient and standardized customer service system. Based on role-based permission design, the system provides differentiated functional modules for ordinary users, customer service agents, and system administrators, balancing user experience and management efficiency, and supporting multi-terminal adaptation to meet all-dimensional needs of enterprises' online customer service scenarios.

## 3. 核心功能模块 (Core Functional Modules)

### 3.1 用户中心 (User Center)

|功能 (Function)|中文描述 (Chinese Description)|English Description|
|---|---|---|
|账号管理|支持用户注册、登录、密码重置，集成手机号/邮箱验证机制，保障账号安全|Supports user registration, login, password reset, and integrates mobile phone/email verification mechanisms to ensure account security|
|个人信息管理|用户可编辑个人资料、查看操作日志、管理消息通知偏好|Users can edit personal information, view operation logs, and manage message notification preferences|
|权限控制|基于RBAC模型实现角色分级（普通用户/客服/管理员），不同角色对应不同操作权限|Implements role grading (ordinary user/customer service/administrator) based on the RBAC model, with different roles corresponding to different operation permissions|
### 3.2 客服交互 (Customer Service Interaction)

|功能 (Function)|中文描述 (Chinese Description)|English Description|
|---|---|---|
|实时在线聊天|支持文字/图片/文件消息交互，集成智能回复模板，提升客服响应效率|Supports text/image/file message interaction, integrates intelligent reply templates to improve customer service response efficiency|
|会话管理|客服可查看待处理/已处理会话列表，支持会话转接、挂起、结束操作|Customer service agents can view pending/processed session lists, and support session transfer, suspension, and termination operations|
|聊天记录追溯|所有会话内容持久化存储，支持按时间/用户/关键词检索，便于问题复盘|All session content is persistently stored, supporting retrieval by time/user/keywords for easy problem review|
### 3.3 预约管理 (Appointment Management)

|功能 (Function)|中文描述 (Chinese Description)|English Description|
|---|---|---|
|服务预约|用户可选择服务类型、预约时段，系统自动校验资源可用性并完成预约|Users can select service types and appointment time slots, and the system automatically verifies resource availability and completes the appointment|
|预约状态管理|支持预约确认、取消、改期操作，同步推送状态变更通知至用户/客服|Supports appointment confirmation, cancellation, and rescheduling operations, and synchronously pushes status change notifications to users/customer service agents|
|服务评价|服务完成后用户可对服务质量评分、填写评语，评价数据同步至管理后台|After service completion, users can rate service quality and fill in comments, and evaluation data is synchronized to the management background|
### 3.4 管理后台 (Admin Backend)

|功能 (Function)|中文描述 (Chinese Description)|English Description|
|---|---|---|
|用户管理|管理员可查看/新增/禁用用户账号，配置用户角色与权限范围|Administrators can view/add/disable user accounts and configure user roles and permission scopes|
|服务配置|自定义服务类型、服务时长、服务人员排班规则，灵活适配业务需求|Customize service types, service duration, and service staff scheduling rules to flexibly adapt to business needs|
|数据统计|生成客服响应率、预约完成率、用户满意度等多维度报表，支持导出|Generates multi-dimensional reports on customer service response rate, appointment completion rate, user satisfaction, etc., with export support|
## 4. 技术架构 (Technical Architecture)

### 4.1 前端技术栈 (Frontend Technology Stack)

- 核心框架 (Core Framework)：Vue 3 + Vite

- UI组件库 (UI Component Library)：Element Plus

- 状态管理 (State Management)：Pinia

- 通信协议 (Communication Protocol)：WebSocket（实时聊天）、Axios（接口请求）

- 适配方案 (Adaptation Solution)：Responsive Layout（响应式布局），支持PC/移动端

### 4.2 后端技术栈 (Backend Technology Stack)

- 开发框架 (Development Framework)：flask 4.2 (Python)

- 数据库 (Database)：SQLite (SQLite)）

- API规范 (API Specification)：RESTful API

- 部署方式 (Deployment Method)：Docker容器化部署

## 5. 部署与使用 (Deployment and Usage)

### 5.1 部署要求 (Deployment Requirements)

|环境 (Environment)|中文要求 (Chinese Requirements)|English Requirements|
|---|---|---|
|服务器配置|CPU：2核及以上；内存：4GB及以上；磁盘：50GB及以上|CPU: 2 cores or above; Memory: 4GB or above; Disk: 50GB or above|
|运行环境|操作系统：Linux (CentOS 7+/Ubuntu 20.04+)；Python 3.9+；Node.js 16+|OS: Linux (CentOS 7+/Ubuntu 20.04+); Python 3.9+; Node.js 16+|
|网络要求|开放80/443端口，支持WebSocket协议|Open ports 80/443 and support WebSocket protocol|
### 5.2 快速启动 (Quick Start)

#### 中文

1. 克隆代码仓库：`git clone https://github.com/xxx/smartsupport.git`

2. 前端部署：进入`frontend`目录，执行`npm install && npm run build`，将dist目录部署至Nginx

3. 后端部署：进入`backend`目录，配置`settings.py`数据库信息，执行`python manage.py migrate`初始化数据库，`python manage.py runserver 0.0.0.0:8000`启动服务

4. 访问系统：浏览器输入服务器IP+端口，默认管理员账号：admin/123456

#### English

1. Clone the code repository: `git clone https://github.com/xxx/smartsupport.git`

2. Frontend deployment: Enter the `frontend` directory, execute `npm install && npm run build`, and deploy the dist directory to Nginx

3. Backend deployment: Enter the `backend` directory, configure the database information in `settings.py`, execute `python manage.py migrate` to initialize the database, and `python manage.py runserver 0.0.0.0:8000` to start the service

4. Access the system: Enter the server IP + port in the browser, default administrator account: admin/123456

## 6. 维护与更新 (Maintenance and Update)

### 中文

1. 数据备份：建议每日定时备份数据库，备份文件存储至独立服务器，避免数据丢失

2. 版本更新：系统迭代更新前需先备份代码与数据，更新后执行数据库迁移脚本

3. 问题反馈：用户可通过系统内置的“意见反馈”模块提交问题，管理员定期处理并优化

### English

1. Data backup: It is recommended to back up the database regularly every day, and store backup files on an independent server to avoid data loss

2. Version update: Back up code and data before system iterative update, and execute database migration scripts after update

3. Issue feedback: Users can submit issues through the built-in "Feedback" module, and administrators handle and optimize them regularly

## 7. 联系方式 (Contact Information)

- 技术支持邮箱 (Technical Support Email)：[support@smartsupport.com](mailto:support@smartsupport.com)

- 开发团队 (Development Team)：SmartSupport Dev Team

- 文档更新时间 (Document Update Time)：2025-12-30